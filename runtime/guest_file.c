#include "guest_file.h"
#include "guest_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/* --- FNV-1a Hash for String Keys --- */
static inline uint32_t vfs_hash(const char *str)
{
    uint32_t h = 2166136261u;
    for (; *str; str++) {
        h ^= (uint8_t)*str;
        h *= 16777619u;
    }
    return h;
}

/* --- TEB LastError Helper --- */
static int set_teb_last_error(CPU *cpu, uint32_t err, uint32_t *fault)
{
    if (!cpu || cpu->fs_base == 0) {
        if (fault) *fault = 0;
        return -2;
    }
    const uint64_t teb_sum = (uint64_t)cpu->fs_base + 0x34ULL;
    if (teb_sum > (uint64_t)UINT32_MAX) {
        if (fault) *fault = UINT32_MAX;
        return -1;
    }
    void *teb_ptr = guest_memory_pointer((uint32_t)teb_sum, 4ULL, 1);
    if (!teb_ptr) {
        if (fault) *fault = (uint32_t)teb_sum;
        return -1;
    }
    memcpy(teb_ptr, &err, sizeof(uint32_t));
    return 0;
}

/* Weak stub for win32_signal_event if runtime/win32.c is not linked */
__attribute__((weak)) void win32_signal_event(uint32_t handle) {
    (void)handle;
}

/* --- Directory Creation Helper (mkdir -p) --- */
static void vfs_mkdir_parents(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *q = tmp + 1; *q; q++) {
        if (*q == '/') {
            *q = '\0';
            mkdir(tmp, 0755);
            *q = '/';
        }
    }
}

/* --- Copy File Helper for Overlay Copy-Up --- */
static int vfs_copy_file(const char *src, const char *dst)
{
    FILE *fa = fopen(src, "rb");
    if (!fa) return 0;
    vfs_mkdir_parents(dst);
    FILE *fb = fopen(dst, "wb");
    if (!fb) {
        fclose(fa);
        return 0;
    }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fa)) > 0) {
        if (fwrite(buf, 1, n, fb) != n) {
            fclose(fb);
            fclose(fa);
            return 0;
        }
    }
    fclose(fb);
    fclose(fa);
    return 1;
}

/* --- Root Path Lookup Helper --- */
static const char *vfs_get_root_path(const GuestVFS *vfs, uint8_t root_id)
{
    if (root_id == GUEST_VFS_ROOT_ID_WRITE) {
        return (vfs->write_root[0] != '\0') ? vfs->write_root : vfs->read_root;
    }
    if (root_id < vfs->root_count && vfs->roots[root_id].active) {
        return vfs->roots[root_id].path;
    }
    if (vfs->read_root[0] != '\0') {
        return vfs->read_root;
    }
    return "";
}

/* --- Path Normalization & Traversal Sandbox Sanitization --- */
static int vfs_normalize_path(const char *win, char *out_canon, size_t out_sz)
{
    if (!win || !out_canon || out_sz == 0) return -1;

    const char *p = win;

    /* Skip drive letter e.g. "C:" or "D:" */
    if (isalpha((unsigned char)p[0]) && p[1] == ':') {
        p += 2;
    }

    /* Skip leading separators */
    while (*p == '\\' || *p == '/') {
        p++;
    }

    /* Skip relative "./" or ".\\" prefixes if present */
    while (p[0] == '.' && (p[1] == '\\' || p[1] == '/')) {
        p += 2;
        while (*p == '\\' || *p == '/') p++;
    }

    /* Skip virtual "NFSU2" root prefix if present */
    if (!strncasecmp(p, "NFSU2", 5) && (p[5] == '\\' || p[5] == '/' || p[5] == '\0')) {
        p += 5;
        while (*p == '\\' || *p == '/') {
            p++;
        }
    }

    /* Skip relative "./" or ".\\" prefixes again after virtual root */
    while (p[0] == '.' && (p[1] == '\\' || p[1] == '/')) {
        p += 2;
        while (*p == '\\' || *p == '/') p++;
    }

    /* Component stack for canonical path */
    char components[32][GUEST_VFS_PATH_MAX];
    int depth = 0;

    char temp[GUEST_VFS_PATH_MAX];
    size_t k = 0;
    while (*p && k < sizeof(temp) - 1) {
        char ch = *p++;
        if (ch == '\\') ch = '/';
        temp[k++] = ch;
    }
    temp[k] = '\0';

    char *save = NULL;
    char *tok = strtok_r(temp, "/", &save);
    while (tok) {
        if (strcmp(tok, ".") == 0) {
            /* Current directory: ignore */
        } else if (strcmp(tok, "..") == 0) {
            /* Directory traversal: reject if escaping virtual root */
            if (depth == 0) {
                return -1; /* Traversal security violation */
            }
            depth--;
        } else {
            if (depth >= 32) {
                return -1; /* Depth limit exceeded */
            }
            /* Trim trailing spaces and dots (Win32 filename rules) */
            size_t clen = strlen(tok);
            while (clen > 0 && (tok[clen - 1] == ' ' || tok[clen - 1] == '.')) {
                tok[--clen] = '\0';
            }
            if (clen == 0) {
                tok = strtok_r(NULL, "/", &save);
                continue;
            }
            if (clen >= GUEST_VFS_PATH_MAX) {
                clen = GUEST_VFS_PATH_MAX - 1;
            }
            for (size_t i = 0; i < clen; i++) {
                components[depth][i] = (char)tolower((unsigned char)tok[i]);
            }
            components[depth][clen] = '\0';
            depth++;
        }
        tok = strtok_r(NULL, "/", &save);
    }

    /* Reassemble canonical path */
    out_canon[0] = '\0';
    size_t cur_len = 0;
    for (int i = 0; i < depth; i++) {
        if (i > 0 && cur_len < out_sz - 1) {
            out_canon[cur_len++] = '/';
            out_canon[cur_len] = '\0';
        }
        size_t slen = strlen(components[i]);
        if (cur_len + slen >= out_sz) {
            return -1;
        }
        memcpy(out_canon + cur_len, components[i], slen);
        cur_len += slen;
        out_canon[cur_len] = '\0';
    }

    return 0;
}

/* --- In-Memory Case Map Cache Operations --- */
static GuestVFSNode *vfs_cache_lookup(GuestVFS *vfs, const char *canon_key,
                                      uint8_t *out_root, char *out_disk_rel)
{
    if (!vfs || !canon_key) return NULL;

    uint32_t hash = vfs_hash(canon_key);
    uint32_t idx = hash & (GUEST_VFS_HASH_BUCKETS - 1);

    for (GuestVFSNode *n = vfs->buckets[idx]; n; n = n->next) {
        if (n->hash == hash && strcmp(n->canonical_key, canon_key) == 0) {
            if (out_root) *out_root = n->root_id;
            if (out_disk_rel) snprintf(out_disk_rel, GUEST_VFS_PATH_MAX, "%s", n->disk_relpath);
            return n;
        }
    }

    return NULL;
}

static int vfs_cache_insert(GuestVFS *vfs, uint8_t root_id, uint8_t priority,
                            const char *canon_key, const char *disk_rel,
                            uint8_t is_dir)
{
    if (!vfs || !canon_key || !disk_rel) return -1;

    uint32_t hash = vfs_hash(canon_key);
    uint32_t idx = hash & (GUEST_VFS_HASH_BUCKETS - 1);

    /* Update existing if found and new entry is higher or equal priority */
    for (GuestVFSNode *n = vfs->buckets[idx]; n; n = n->next) {
        if (n->hash == hash && strcmp(n->canonical_key, canon_key) == 0) {
            if (priority < n->priority || (priority == n->priority && n->root_id == root_id)) {
                snprintf(n->disk_relpath, sizeof(n->disk_relpath), "%s", disk_rel);
                n->root_id = root_id;
                n->priority = priority;
                n->is_dir = is_dir;
            }
            return 0;
        }
    }

    /* Expand pool if needed */
    if (vfs->node_count >= vfs->node_capacity) {
        size_t new_cap = vfs->node_capacity == 0 ? 1024 : vfs->node_capacity * 2;
        GuestVFSNode *new_pool = (GuestVFSNode *)realloc(vfs->node_pool, new_cap * sizeof(GuestVFSNode));
        if (!new_pool) return -1;

        /* Re-link buckets if memory moved */
        if (new_pool != vfs->node_pool && vfs->node_pool != NULL) {
            ptrdiff_t diff = (uint8_t *)new_pool - (uint8_t *)vfs->node_pool;
            for (size_t b = 0; b < GUEST_VFS_HASH_BUCKETS; b++) {
                if (vfs->buckets[b]) {
                    vfs->buckets[b] = (GuestVFSNode *)((uint8_t *)vfs->buckets[b] + diff);
                }
            }
            for (size_t i = 0; i < vfs->node_count; i++) {
                if (new_pool[i].next) {
                    new_pool[i].next = (GuestVFSNode *)((uint8_t *)new_pool[i].next + diff);
                }
            }
        }
        vfs->node_pool = new_pool;
        vfs->node_capacity = new_cap;
    }

    GuestVFSNode *node = &vfs->node_pool[vfs->node_count++];
    memset(node, 0, sizeof(*node));
    node->hash = hash;
    snprintf(node->canonical_key, sizeof(node->canonical_key), "%s", canon_key);
    snprintf(node->disk_relpath, sizeof(node->disk_relpath), "%s", disk_rel);
    node->root_id = root_id;
    node->priority = priority;
    node->is_dir = is_dir;

    node->next = vfs->buckets[idx];
    vfs->buckets[idx] = node;

    return 0;
}

/* --- Recursive Directory Indexer --- */
static void vfs_index_recursive(GuestVFS *vfs, const char *root_abs,
                                const char *rel_dir, uint8_t root_id, uint8_t priority)
{
    char full_dir[1024];
    if (rel_dir && rel_dir[0]) {
        snprintf(full_dir, sizeof(full_dir), "%s/%s", root_abs, rel_dir);
    } else {
        snprintf(full_dir, sizeof(full_dir), "%s", root_abs);
    }

    DIR *d = opendir(full_dir);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }
        /* Skip macOS metadata and AppleDouble files */
        if (e->d_name[0] == '.' && (strcmp(e->d_name, ".DS_Store") == 0 || e->d_name[1] == '_')) {
            continue;
        }

        char item_rel[GUEST_VFS_PATH_MAX];
        if (rel_dir && rel_dir[0]) {
            snprintf(item_rel, sizeof(item_rel), "%s/%s", rel_dir, e->d_name);
        } else {
            snprintf(item_rel, sizeof(item_rel), "%s", e->d_name);
        }

        char canon[GUEST_VFS_PATH_MAX];
        if (vfs_normalize_path(item_rel, canon, sizeof(canon)) == 0) {
            uint8_t is_dir = 0;
            if (e->d_type == DT_DIR) {
                is_dir = 1;
            } else if (e->d_type == DT_UNKNOWN) {
                char full_item[1024];
                snprintf(full_item, sizeof(full_item), "%s/%s", root_abs, item_rel);
                struct stat st;
                if (stat(full_item, &st) == 0 && S_ISDIR(st.st_mode)) {
                    is_dir = 1;
                }
            }

            vfs_cache_insert(vfs, root_id, priority, canon, item_rel, is_dir);

            if (is_dir) {
                vfs_index_recursive(vfs, root_abs, item_rel, root_id, priority);
            }
        }
    }
    closedir(d);
}

/* --- Lazy On-Disk Case-Insensitive Step Search with Fast Stat Path --- */
static int vfs_step_resolve(const char *root, const char *canon_path,
                            char *out_disk_rel, size_t out_sz)
{
    if (!root || !root[0] || !canon_path) return 0;

    char cur[1024];
    snprintf(cur, sizeof(cur), "%s", root);

    char tmp[GUEST_VFS_PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", canon_path);

    char disk_rel[GUEST_VFS_PATH_MAX] = "";
    char *save = NULL;
    int missing = 0;

    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (missing) {
            return 0;
        }

        /* Fast-path: Check exact case with stat before opening directory */
        char direct_cand[1024];
        snprintf(direct_cand, sizeof(direct_cand), "%s/%s", cur, tok);
        struct stat st_direct;
        if (stat(direct_cand, &st_direct) == 0) {
            snprintf(cur, sizeof(cur), "%s", direct_cand);
            if (disk_rel[0]) {
                size_t dlen = strlen(disk_rel);
                snprintf(disk_rel + dlen, sizeof(disk_rel) - dlen, "/%s", tok);
            } else {
                snprintf(disk_rel, sizeof(disk_rel), "%s", tok);
            }
            continue;
        }

        /* Case-insensitive directory enumeration fallback for APFS */
        DIR *d = opendir(cur);
        if (!d) {
            return 0;
        }
        struct dirent *e;
        int found = 0;
        char matched_name[256];
        while ((e = readdir(d)) != NULL) {
            if (strcasecmp(e->d_name, tok) == 0) {
                snprintf(matched_name, sizeof(matched_name), "%s", e->d_name);
                found = 1;
                break;
            }
        }
        closedir(d);

        if (found) {
            size_t cur_len = strlen(cur);
            snprintf(cur + cur_len, sizeof(cur) - cur_len, "/%s", matched_name);
            if (disk_rel[0]) {
                size_t dlen = strlen(disk_rel);
                snprintf(disk_rel + dlen, sizeof(disk_rel) - dlen, "/%s", matched_name);
            } else {
                snprintf(disk_rel, sizeof(disk_rel), "%s", matched_name);
            }
        } else {
            missing = 1;
        }
    }

    if (!missing && disk_rel[0]) {
        snprintf(out_disk_rel, out_sz, "%s", disk_rel);
        return 1;
    }
    return 0;
}

/* --- Public VFS Resolution API --- */
int guest_vfs_resolve(GuestVFS *vfs, const char *win_path, int for_write,
                      char *out_host_path, size_t out_host_sz,
                      char *out_canonical_rel, size_t out_rel_sz)
{
    if (!vfs || !win_path || !out_host_path) return -1;

    char canon[GUEST_VFS_PATH_MAX];
    if (vfs_normalize_path(win_path, canon, sizeof(canon)) != 0) {
        return -2; /* Traversal violation */
    }

    if (out_canonical_rel && out_rel_sz > 0) {
        snprintf(out_canonical_rel, out_rel_sz, "%s", canon);
    }

    pthread_mutex_lock(&vfs->lock);

    /* For write operations: target write_root */
    if (for_write) {
        const char *wroot = (vfs->write_root[0] != '\0') ? vfs->write_root : vfs->read_root;
        uint8_t root_id;
        char disk_rel[GUEST_VFS_PATH_MAX];
        GuestVFSNode *cached = vfs_cache_lookup(vfs, canon, &root_id, disk_rel);

        if (cached && root_id == GUEST_VFS_ROOT_ID_WRITE) {
            snprintf(out_host_path, out_host_sz, "%s/%s", wroot, disk_rel);
        } else {
            /* Create new entry with canonical name */
            snprintf(out_host_path, out_host_sz, "%s/%s", wroot, canon);
            vfs_cache_insert(vfs, GUEST_VFS_ROOT_ID_WRITE, GUEST_VFS_PRIORITY_WRITE, canon, canon, 0);
        }
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* For read operations: check in-memory cache first (O(1)) */
    uint8_t root_id = 0;
    char disk_rel[GUEST_VFS_PATH_MAX];
    GuestVFSNode *cached = vfs_cache_lookup(vfs, canon, &root_id, disk_rel);

    if (cached) {
        const char *base = vfs_get_root_path(vfs, root_id);
        snprintf(out_host_path, out_host_sz, "%s/%s", base, disk_rel);
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* Cache miss: check on disk in write_root (user saves / modifications) */
    if (vfs->write_root[0] && vfs_step_resolve(vfs->write_root, canon, disk_rel, sizeof(disk_rel))) {
        snprintf(out_host_path, out_host_sz, "%s/%s", vfs->write_root, disk_rel);
        vfs_cache_insert(vfs, GUEST_VFS_ROOT_ID_WRITE, GUEST_VFS_PRIORITY_WRITE, canon, disk_rel, 0);
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* Cache miss: check multi-root search paths in priority order */
    for (size_t r = 0; r < vfs->root_count; r++) {
        if (!vfs->roots[r].active || !vfs->roots[r].path[0]) continue;
        if (vfs_step_resolve(vfs->roots[r].path, canon, disk_rel, sizeof(disk_rel))) {
            snprintf(out_host_path, out_host_sz, "%s/%s", vfs->roots[r].path, disk_rel);
            vfs_cache_insert(vfs, (uint8_t)r, vfs->roots[r].priority, canon, disk_rel, 0);
            pthread_mutex_unlock(&vfs->lock);
            return 0;
        }
    }

    /* Cache miss: legacy read_root fallback */
    if (vfs->read_root[0] && vfs_step_resolve(vfs->read_root, canon, disk_rel, sizeof(disk_rel))) {
        snprintf(out_host_path, out_host_sz, "%s/%s", vfs->read_root, disk_rel);
        vfs_cache_insert(vfs, 0, GUEST_VFS_PRIORITY_FALLBACK, canon, disk_rel, 0);
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* Video suffix fallback (e.g. "_fr.vp6" -> "_en.vp6" -> ".vp6") */
    const char *dot = strrchr(canon, '.');
    if (dot && (!strcasecmp(dot, ".vp6") || !strcasecmp(dot, ".bik") || !strcasecmp(dot, ".mpg"))) {
        size_t base_len = (size_t)(dot - canon);
        size_t cut = base_len;
        if (base_len >= 3 && canon[base_len - 3] == '_') {
            cut = base_len - 3;
        }
        const char *sfx[] = { "_en", "", "_dn", "_du", "_sw" };
        for (int q = 0; q < 5; q++) {
            char alt[GUEST_VFS_PATH_MAX];
            snprintf(alt, sizeof(alt), "%.*s%s%s", (int)cut, canon, sfx[q], dot);
            cached = vfs_cache_lookup(vfs, alt, &root_id, disk_rel);
            if (cached) {
                const char *base = vfs_get_root_path(vfs, root_id);
                snprintf(out_host_path, out_host_sz, "%s/%s", base, disk_rel);
                pthread_mutex_unlock(&vfs->lock);
                return 0;
            }
            /* Step resolve fallback for video suffixes */
            for (size_t r = 0; r < vfs->root_count; r++) {
                if (!vfs->roots[r].active || !vfs->roots[r].path[0]) continue;
                if (vfs_step_resolve(vfs->roots[r].path, alt, disk_rel, sizeof(disk_rel))) {
                    snprintf(out_host_path, out_host_sz, "%s/%s", vfs->roots[r].path, disk_rel);
                    vfs_cache_insert(vfs, (uint8_t)r, vfs->roots[r].priority, alt, disk_rel, 0);
                    pthread_mutex_unlock(&vfs->lock);
                    return 0;
                }
            }
        }
    }

    pthread_mutex_unlock(&vfs->lock);
    return -3; /* File not found */
}

/* --- File Table Lifecycle --- */
int guest_file_init(GuestFileTable *table, const char *read_root, const char *write_root)
{
    if (!table) return -1;
    memset(table, 0, sizeof(*table));

    pthread_mutex_init(&table->vfs.lock, NULL);
    pthread_mutex_init(&table->lock, NULL);

    for (size_t i = 0; i < GUEST_FILE_HANDLE_MAX; i++) {
        pthread_mutex_init(&table->slots[i].slot_lock, NULL);
        table->slots[i].fd = -1;
    }

    table->vfs.initialized = 1;
    table->initialized = 1;

    guest_file_set_roots(table, read_root, write_root);
    return 0;
}

int guest_file_set_roots(GuestFileTable *table, const char *read_root, const char *write_root)
{
    if (!table || !table->initialized) return -1;

    pthread_mutex_lock(&table->vfs.lock);
    if (read_root && read_root[0]) {
        snprintf(table->vfs.read_root, sizeof(table->vfs.read_root), "%s", read_root);
        int found = 0;
        for (size_t i = 0; i < table->vfs.root_count; i++) {
            if (strcmp(table->vfs.roots[i].path, read_root) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && table->vfs.root_count < GUEST_VFS_MAX_SEARCH_ROOTS) {
            size_t idx = table->vfs.root_count++;
            snprintf(table->vfs.roots[idx].path, sizeof(table->vfs.roots[idx].path), "%s", read_root);
            table->vfs.roots[idx].priority = GUEST_VFS_PRIORITY_BUNDLE;
            table->vfs.roots[idx].is_writable = 0;
            table->vfs.roots[idx].active = 1;
        }
    } else {
        table->vfs.read_root[0] = '\0';
    }

    if (write_root && write_root[0]) {
        snprintf(table->vfs.write_root, sizeof(table->vfs.write_root), "%s", write_root);
        vfs_mkdir_parents(table->vfs.write_root);
        mkdir(table->vfs.write_root, 0755);
    } else {
        table->vfs.write_root[0] = '\0';
    }
    pthread_mutex_unlock(&table->vfs.lock);

    return 0;
}

int guest_file_add_root(GuestFileTable *table, const char *path, uint8_t priority, int is_writable)
{
    if (!table || !table->initialized || !path || !path[0]) return -1;

    pthread_mutex_lock(&table->vfs.lock);
    if (table->vfs.root_count >= GUEST_VFS_MAX_SEARCH_ROOTS) {
        pthread_mutex_unlock(&table->vfs.lock);
        return -2;
    }

    /* Check if already registered */
    for (size_t i = 0; i < table->vfs.root_count; i++) {
        if (strcmp(table->vfs.roots[i].path, path) == 0) {
            table->vfs.roots[i].priority = priority;
            table->vfs.roots[i].is_writable = (uint8_t)(is_writable ? 1 : 0);
            table->vfs.roots[i].active = 1;
            pthread_mutex_unlock(&table->vfs.lock);
            return 0;
        }
    }

    size_t idx = table->vfs.root_count++;
    snprintf(table->vfs.roots[idx].path, sizeof(table->vfs.roots[idx].path), "%s", path);
    table->vfs.roots[idx].priority = priority;
    table->vfs.roots[idx].is_writable = (uint8_t)(is_writable ? 1 : 0);
    table->vfs.roots[idx].active = 1;

    /* Sort roots by priority ascending (lower priority value = higher precedence) */
    for (size_t i = 0; i < table->vfs.root_count; i++) {
        for (size_t j = i + 1; j < table->vfs.root_count; j++) {
            if (table->vfs.roots[j].priority < table->vfs.roots[i].priority) {
                GuestVFSRoot tmp = table->vfs.roots[i];
                table->vfs.roots[i] = table->vfs.roots[j];
                table->vfs.roots[j] = tmp;
            }
        }
    }

    pthread_mutex_unlock(&table->vfs.lock);
    return 0;
}

int guest_file_setup_ios_roots(GuestFileTable *table,
                               const char *documents_dir,
                               const char *bundle_dir,
                               const char *app_support_dir)
{
    if (!table || !table->initialized) return -1;

    /* Priority 1: <Documents>/Game/ (User/mod files) */
    if (documents_dir && documents_dir[0]) {
        char doc_game[1024];
        snprintf(doc_game, sizeof(doc_game), "%s/Game", documents_dir);
        struct stat st;
        if (stat(doc_game, &st) == 0 && S_ISDIR(st.st_mode)) {
            guest_file_add_root(table, doc_game, GUEST_VFS_PRIORITY_DOCUMENTS, 1);
        } else {
            guest_file_add_root(table, documents_dir, GUEST_VFS_PRIORITY_DOCUMENTS, 1);
        }
        if (!table->vfs.write_root[0]) {
            guest_file_set_roots(table, NULL, doc_game);
        }
    }

    /* Priority 2: <AppBundle>/Game/ or <AppBundle>/ (Embedded assets) */
    if (bundle_dir && bundle_dir[0]) {
        char bundle_game[1024];
        snprintf(bundle_game, sizeof(bundle_game), "%s/Game", bundle_dir);
        struct stat st;
        if (stat(bundle_game, &st) == 0 && S_ISDIR(st.st_mode)) {
            guest_file_add_root(table, bundle_game, GUEST_VFS_PRIORITY_BUNDLE, 0);
        } else {
            guest_file_add_root(table, bundle_dir, GUEST_VFS_PRIORITY_BUNDLE, 0);
        }
    }

    /* Priority 3: <Application Support>/NFSU2/Game/ (Base installed assets) */
    if (app_support_dir && app_support_dir[0]) {
        char app_game[1024];
        snprintf(app_game, sizeof(app_game), "%s/NFSU2/Game", app_support_dir);
        struct stat st;
        if (stat(app_game, &st) == 0 && S_ISDIR(st.st_mode)) {
            guest_file_add_root(table, app_game, GUEST_VFS_PRIORITY_APP_SUPPORT, 1);
        } else {
            guest_file_add_root(table, app_support_dir, GUEST_VFS_PRIORITY_APP_SUPPORT, 1);
        }
        if (!table->vfs.write_root[0]) {
            guest_file_set_roots(table, NULL, app_game);
        }
    }

    return 0;
}

int guest_file_index_roots(GuestFileTable *table)
{
    if (!table || !table->initialized) return -1;

    pthread_mutex_lock(&table->vfs.lock);

    /* Index active asset roots in REVERSE priority order (lowest priority first,
     * so that higher priority roots will overwrite duplicate entries in the cache). */
    for (ssize_t i = (ssize_t)table->vfs.root_count - 1; i >= 0; i--) {
        if (table->vfs.roots[i].active && table->vfs.roots[i].path[0]) {
            vfs_index_recursive(&table->vfs, table->vfs.roots[i].path, "",
                                (uint8_t)i, table->vfs.roots[i].priority);
        }
    }

    /* Index write_root with highest priority (0) so saved/modified files always take precedence */
    if (table->vfs.write_root[0]) {
        vfs_index_recursive(&table->vfs, table->vfs.write_root, "",
                            GUEST_VFS_ROOT_ID_WRITE, GUEST_VFS_PRIORITY_WRITE);
    }

    pthread_mutex_unlock(&table->vfs.lock);
    return 0;
}

int guest_file_cleanup(GuestFileTable *table)
{
    if (!table || !table->initialized) return 0;

    pthread_mutex_lock(&table->lock);
    for (size_t i = 1; i < GUEST_FILE_HANDLE_MAX; i++) {
        if (table->slots[i].in_use && table->slots[i].fd >= 0) {
            close(table->slots[i].fd);
            table->slots[i].fd = -1;
            table->slots[i].in_use = 0;
        }
        table->slots[i].closing = 0;
        table->slots[i].refcount = 0;
    }
    table->active_handles = 0;
    pthread_mutex_unlock(&table->lock);

    for (size_t i = 0; i < GUEST_FILE_HANDLE_MAX; i++) {
        pthread_mutex_destroy(&table->slots[i].slot_lock);
    }

    pthread_mutex_lock(&table->vfs.lock);
    if (table->vfs.node_pool) {
        free(table->vfs.node_pool);
        table->vfs.node_pool = NULL;
    }
    table->vfs.node_count = 0;
    table->vfs.node_capacity = 0;
    table->vfs.root_count = 0;
    memset(table->vfs.roots, 0, sizeof(table->vfs.roots));
    memset(table->vfs.buckets, 0, sizeof(table->vfs.buckets));
    pthread_mutex_unlock(&table->vfs.lock);

    pthread_mutex_destroy(&table->vfs.lock);
    pthread_mutex_destroy(&table->lock);
    table->initialized = 0;
    return 0;
}

/* --- Internal Handle Allocator & Lookup with Refcounting --- */
static uint32_t alloc_handle(GuestFileTable *table, int fd, int is_empty,
                             uint32_t access, uint32_t disp, const char *rel)
{
    pthread_mutex_lock(&table->lock);
    for (uint32_t i = 1; i < GUEST_FILE_HANDLE_MAX; i++) {
        if (!table->slots[i].in_use && !table->slots[i].closing && table->slots[i].refcount == 0) {
            table->slots[i].in_use = 1;
            table->slots[i].closing = 0;
            table->slots[i].refcount = 0;
            table->slots[i].fd = fd;
            table->slots[i].is_empty = is_empty;
            table->slots[i].access = access;
            table->slots[i].disposition = disp;
            if (rel) {
                snprintf(table->slots[i].rel_path, sizeof(table->slots[i].rel_path), "%s", rel);
            } else {
                table->slots[i].rel_path[0] = '\0';
            }
            table->active_handles++;
            pthread_mutex_unlock(&table->lock);
            return GUEST_FILE_HANDLE_BASE + i;
        }
    }
    pthread_mutex_unlock(&table->lock);
    return GUEST_INVALID_HANDLE_VALUE;
}

static GuestFileSlot *retain_slot(GuestFileTable *table, uint32_t h)
{
    if (h < GUEST_FILE_HANDLE_BASE + 1 || h >= GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX) {
        return NULL;
    }
    uint32_t idx = h - GUEST_FILE_HANDLE_BASE;
    pthread_mutex_lock(&table->lock);
    if (!table->slots[idx].in_use || table->slots[idx].closing || table->slots[idx].fd < 0) {
        pthread_mutex_unlock(&table->lock);
        return NULL;
    }
    table->slots[idx].refcount++;
    pthread_mutex_unlock(&table->lock);
    return &table->slots[idx];
}

static void release_slot(GuestFileTable *table, GuestFileSlot *slot)
{
    if (!table || !slot) return;
    pthread_mutex_lock(&table->lock);
    if (slot->refcount > 0) {
        slot->refcount--;
    }
    if (slot->refcount == 0 && slot->closing) {
        if (slot->fd >= 0) {
            close(slot->fd);
            slot->fd = -1;
        }
        slot->in_use = 0;
        slot->closing = 0;
        slot->is_empty = 0;
        if (table->active_handles > 0) {
            table->active_handles--;
        }
    }
    pthread_mutex_unlock(&table->lock);
}

static int free_handle(GuestFileTable *table, uint32_t h)
{
    if (h < GUEST_FILE_HANDLE_BASE + 1 || h >= GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX) {
        return 0;
    }
    uint32_t idx = h - GUEST_FILE_HANDLE_BASE;
    pthread_mutex_lock(&table->lock);
    if (!table->slots[idx].in_use || table->slots[idx].closing) {
        pthread_mutex_unlock(&table->lock);
        return 0;
    }

    if (table->slots[idx].refcount == 0) {
        if (table->slots[idx].fd >= 0) {
            close(table->slots[idx].fd);
            table->slots[idx].fd = -1;
        }
        table->slots[idx].in_use = 0;
        table->slots[idx].closing = 0;
        table->slots[idx].is_empty = 0;
        if (table->active_handles > 0) {
            table->active_handles--;
        }
    } else {
        /* Deferred close: active asynchronous I/O will close fd when refcount drops to 0 */
        table->slots[idx].closing = 1;
    }
    pthread_mutex_unlock(&table->lock);
    return 1;
}

/* =========================================================================
 * Win32 Guest Import Implementations
 * ========================================================================= */

/* --- CreateFileA (argc 7, frame 32 bytes) --- */
static int handle_create_file_a(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 32ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, pn, access, share, sec, disp, flags_attr, template_h;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&pn, f + 4, 4);
    memcpy(&access, f + 8, 4);
    memcpy(&share, f + 12, 4);
    memcpy(&sec, f + 16, 4);
    memcpy(&disp, f + 20, 4);
    memcpy(&flags_attr, f + 24, 4);
    memcpy(&template_h, f + 28, 4);
    (void)share; (void)sec; (void)flags_attr; (void)template_h;

    /* Read null-terminated string from guest memory */
    char win_path[GUEST_VFS_PATH_MAX];
    size_t k = 0;
    while (k < sizeof(win_path) - 1) {
        const char *ch_ptr = (const char *)guest_memory_pointer(pn + (uint32_t)k, 1ULL, 0);
        if (!ch_ptr) {
            *fault = pn + (uint32_t)k;
            return -1;
        }
        win_path[k] = *ch_ptr;
        if (win_path[k] == '\0') break;
        k++;
    }
    win_path[k] = '\0';

    int is_write = (disp == GUEST_CREATE_ALWAYS || disp == GUEST_CREATE_NEW ||
                    disp == GUEST_OPEN_ALWAYS || (access & GUEST_GENERIC_WRITE));

    char host_path[1024];
    char canon_rel[GUEST_VFS_PATH_MAX];
    int res = guest_vfs_resolve(&table->vfs, win_path, is_write,
                                host_path, sizeof(host_path),
                                canon_rel, sizeof(canon_rel));

    if (res == -2) {
        /* Traversal / sandbox violation */
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_PATH_NOT_FOUND, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_HANDLE_VALUE;
        cpu->eip = ret_addr;
        cpu->esp += 32U;
        return 1;
    }

    if (!is_write && res == -3) {
        /* File not found */
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_FILE_NOT_FOUND, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_HANDLE_VALUE;
        cpu->eip = ret_addr;
        cpu->esp += 32U;
        return 1;
    }

    /* Translate Win32 disposition & access to POSIX open flags */
    int flags = 0;
    if (disp == GUEST_CREATE_ALWAYS) {
        flags = O_RDWR | O_CREAT | O_TRUNC;
    } else if (disp == GUEST_CREATE_NEW) {
        flags = O_RDWR | O_CREAT | O_EXCL;
    } else if (disp == GUEST_OPEN_ALWAYS) {
        flags = O_RDWR | O_CREAT;
    } else if (disp == GUEST_TRUNCATE_EXISTING) {
        flags = O_RDWR | O_TRUNC;
    } else {
        flags = (access & GUEST_GENERIC_WRITE) ? O_RDWR : O_RDONLY;
    }

    /* If creating, ensure directory structure exists */
    if (flags & O_CREAT) {
        vfs_mkdir_parents(host_path);
    }

    /* Copy-up logic for save overlays */
    if (is_write && !(flags & O_TRUNC) && table->vfs.write_root[0]) {
        struct stat st;
        if (stat(host_path, &st) != 0) {
            char src_path[1024];
            if (guest_vfs_resolve(&table->vfs, win_path, 0, src_path, sizeof(src_path), NULL, 0) == 0) {
                if (strcmp(src_path, host_path) != 0) {
                    vfs_copy_file(src_path, host_path);
                }
            }
        }
    }

    /* NOMOVIES environment variable check */
    int is_empty = 0;
    const char *ext = strrchr(host_path, '.');
    const char *nomovies_env = getenv("NOMOVIES");
    int movie_mode = (nomovies_env && *nomovies_env && *nomovies_env != '0') ? atoi(nomovies_env) : 0;

    int fd = -1;
    if (movie_mode == 1 && ext &&
        (!strcasecmp(ext, ".vp6") || !strcasecmp(ext, ".vp8") ||
         !strcasecmp(ext, ".bik") || !strcasecmp(ext, ".mpg"))) {
        fd = -1; /* Skip */
    } else if (movie_mode == 2 && ext &&
               (!strcasecmp(ext, ".vp6") || !strcasecmp(ext, ".vp8") ||
                !strcasecmp(ext, ".bik") || !strcasecmp(ext, ".mpg"))) {
        fd = open(host_path, flags, 0644);
        if (fd >= 0) is_empty = 1;
    } else {
        fd = open(host_path, flags, 0644);
    }

    if (fd < 0) {
        uint32_t err = (errno == EEXIST) ? GUEST_ERROR_FILE_EXISTS :
                       (errno == EACCES) ? GUEST_ERROR_ACCESS_DENIED : GUEST_ERROR_FILE_NOT_FOUND;
        int err_rc = set_teb_last_error(cpu, err, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_HANDLE_VALUE;
    } else {
        uint32_t h = alloc_handle(table, fd, is_empty, access, disp, canon_rel);
        if (h == GUEST_INVALID_HANDLE_VALUE) {
            close(fd);
            int err_rc = set_teb_last_error(cpu, GUEST_ERROR_TOO_MANY_OPEN_FILES, fault);
            if (err_rc) return err_rc;
            cpu->eax = GUEST_INVALID_HANDLE_VALUE;
        } else {
            cpu->eax = h;
        }
    }

    cpu->eip = ret_addr;
    cpu->esp += 32U;
    return 1;
}

/* --- ReadFile (argc 5, frame 24 bytes) --- */
static int handle_read_file(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 24ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile, buf, len, pnr, ov;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);
    memcpy(&buf, f + 8, 4);
    memcpy(&len, f + 12, 4);
    memcpy(&pnr, f + 16, 4);
    memcpy(&ov, f + 20, 4);

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        if (pnr) {
            void *pnr_ptr = guest_memory_pointer(pnr, 4ULL, 1);
            if (pnr_ptr) {
                uint32_t zero = 0;
                memcpy(pnr_ptr, &zero, 4);
            }
        }
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
        cpu->eip = ret_addr;
        cpu->esp += 24U;
        return 1;
    }

    /* Validate destination buffer */
    void *buf_ptr = NULL;
    if (len > 0) {
        buf_ptr = guest_memory_pointer(buf, (uint64_t)len, 1);
        if (!buf_ptr) {
            release_slot(table, slot);
            *fault = buf;
            return -1;
        }
    }

    ssize_t got = 0;

    /* Overlapped read branch (Stateless & reentrant: pread can run fully concurrently across threads) */
    if (ov != 0) {
        void *ov_ptr = guest_memory_pointer(ov, 20ULL, 1);
        if (!ov_ptr) {
            release_slot(table, slot);
            *fault = ov;
            return -1;
        }
        uint32_t off_low, off_high, hev;
        memcpy(&off_low, (uint8_t *)ov_ptr + 8, 4);
        memcpy(&off_high, (uint8_t *)ov_ptr + 12, 4);
        memcpy(&hev, (uint8_t *)ov_ptr + 16, 4);

        uint64_t full_off = ((uint64_t)off_high << 32) | (uint64_t)off_low;
        if (len > 0 && buf_ptr) {
            got = pread(slot->fd, buf_ptr, (size_t)len, (off_t)full_off);
            if (got < 0) got = 0;
        }

        /* Write OVERLAPPED completion status */
        uint32_t status_success = 0;
        uint32_t bytes_read = (uint32_t)got;
        memcpy((uint8_t *)ov_ptr + 0, &status_success, 4);
        memcpy((uint8_t *)ov_ptr + 4, &bytes_read, 4);

        if (hev != 0) {
            win32_signal_event(hev);
        }
    } else if (slot->is_empty) {
        got = 0; /* Instant EOF */
    } else {
        if (len > 0 && buf_ptr) {
            pthread_mutex_lock(&slot->slot_lock);
            got = read(slot->fd, buf_ptr, (size_t)len);
            pthread_mutex_unlock(&slot->slot_lock);
            if (got < 0) got = 0;
        }
    }

    release_slot(table, slot);

    if (pnr != 0) {
        void *pnr_ptr = guest_memory_pointer(pnr, 4ULL, 1);
        if (!pnr_ptr) {
            *fault = pnr;
            return -1;
        }
        uint32_t bytes_read = (uint32_t)got;
        memcpy(pnr_ptr, &bytes_read, 4);
    }

    cpu->eax = 1U;
    cpu->eip = ret_addr;
    cpu->esp += 24U;
    return 1;
}

/* --- WriteFile (argc 5, frame 24 bytes) --- */
static int handle_write_file(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 24ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile, buf, len, pnw, ov;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);
    memcpy(&buf, f + 8, 4);
    memcpy(&len, f + 12, 4);
    memcpy(&pnw, f + 16, 4);
    memcpy(&ov, f + 20, 4);
    (void)ov;

    /* Handle standard console handles 0x10 - 0x13 */
    if (hfile >= 0x10u && hfile <= 0x13u) {
        if (len > 0) {
            const void *buf_ptr = guest_memory_pointer(buf, (uint64_t)len, 0);
            if (!buf_ptr) {
                *fault = buf;
                return -1;
            }
            fwrite(buf_ptr, 1, len, stdout);
            fflush(stdout);
        }
        if (pnw != 0) {
            void *pnw_ptr = guest_memory_pointer(pnw, 4ULL, 1);
            if (pnw_ptr) memcpy(pnw_ptr, &len, 4);
        }
        cpu->eax = 1U;
        cpu->eip = ret_addr;
        cpu->esp += 24U;
        return 1;
    }

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        if (pnw) {
            void *pnw_ptr = guest_memory_pointer(pnw, 4ULL, 1);
            if (pnw_ptr) {
                uint32_t zero = 0;
                memcpy(pnw_ptr, &zero, 4);
            }
        }
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
        cpu->eip = ret_addr;
        cpu->esp += 24U;
        return 1;
    }

    const void *buf_ptr = NULL;
    if (len > 0) {
        buf_ptr = guest_memory_pointer(buf, (uint64_t)len, 0);
        if (!buf_ptr) {
            release_slot(table, slot);
            *fault = buf;
            return -1;
        }
    }

    ssize_t written = 0;
    if (len > 0 && buf_ptr) {
        pthread_mutex_lock(&slot->slot_lock);
        written = write(slot->fd, buf_ptr, (size_t)len);
        pthread_mutex_unlock(&slot->slot_lock);
        if (written < 0) written = 0;
    }

    release_slot(table, slot);

    if (pnw != 0) {
        void *pnw_ptr = guest_memory_pointer(pnw, 4ULL, 1);
        if (!pnw_ptr) {
            *fault = pnw;
            return -1;
        }
        uint32_t bytes_written = (uint32_t)written;
        memcpy(pnw_ptr, &bytes_written, 4);
    }

    cpu->eax = 1U;
    cpu->eip = ret_addr;
    cpu->esp += 24U;
    return 1;
}

/* --- SetFilePointer (argc 4, frame 20 bytes) --- */
static int handle_set_file_pointer(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 20ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile, dist_low, dist_high_ptr, method;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);
    memcpy(&dist_low, f + 8, 4);
    memcpy(&dist_high_ptr, f + 12, 4);
    memcpy(&method, f + 16, 4);

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_SET_FILE_POINTER;
        cpu->eip = ret_addr;
        cpu->esp += 20U;
        return 1;
    }

    int whence = (method == GUEST_FILE_BEGIN) ? SEEK_SET :
                 (method == GUEST_FILE_CURRENT) ? SEEK_CUR :
                 (method == GUEST_FILE_END) ? SEEK_END : -1;

    if (whence == -1) {
        release_slot(table, slot);
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_PARAMETER, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_SET_FILE_POINTER;
        cpu->eip = ret_addr;
        cpu->esp += 20U;
        return 1;
    }

    int64_t full_dist = (int32_t)dist_low;
    if (dist_high_ptr != 0) {
        void *high_ptr = guest_memory_pointer(dist_high_ptr, 4ULL, 1);
        if (!high_ptr) {
            release_slot(table, slot);
            *fault = dist_high_ptr;
            return -1;
        }
        int32_t high_val;
        memcpy(&high_val, high_ptr, 4);
        full_dist = (int64_t)(((uint64_t)(uint32_t)high_val << 32) | (uint64_t)dist_low);
    }

    pthread_mutex_lock(&slot->slot_lock);
    off_t pos = lseek(slot->fd, (off_t)full_dist, whence);
    pthread_mutex_unlock(&slot->slot_lock);
    release_slot(table, slot);

    if (pos < 0) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_NEGATIVE_SEEK, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_SET_FILE_POINTER;
    } else {
        cpu->eax = (uint32_t)pos;
        if (dist_high_ptr != 0) {
            void *high_ptr = guest_memory_pointer(dist_high_ptr, 4ULL, 1);
            if (high_ptr) {
                uint32_t high_res = (uint32_t)((uint64_t)pos >> 32);
                memcpy(high_ptr, &high_res, 4);
            }
        }
    }

    cpu->eip = ret_addr;
    cpu->esp += 20U;
    return 1;
}

/* --- CloseHandle (argc 1, frame 8 bytes) --- */
static int handle_close_handle(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);

    /* If not in file handle range, return 0 (not handled, let other subsystems handle) */
    if (hfile < GUEST_FILE_HANDLE_BASE + 1 || hfile >= GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX) {
        return 0;
    }

    int freed = free_handle(table, hfile);
    if (!freed) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
    } else {
        cpu->eax = 1U;
    }

    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* --- GetFileSize (argc 2, frame 12 bytes) --- */
static int handle_get_file_size(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile, p_high;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);
    memcpy(&p_high, f + 8, 4);

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_FILE_SIZE;
        cpu->eip = ret_addr;
        cpu->esp += 12U;
        return 1;
    }

    if (slot->is_empty) {
        release_slot(table, slot);
        cpu->eax = 0U;
        if (p_high != 0) {
            void *high_ptr = guest_memory_pointer(p_high, 4ULL, 1);
            if (!high_ptr) {
                *fault = p_high;
                return -1;
            }
            uint32_t zero = 0;
            memcpy(high_ptr, &zero, 4);
        }
        cpu->eip = ret_addr;
        cpu->esp += 12U;
        return 1;
    }

    struct stat st;
    int stat_rc = fstat(slot->fd, &st);
    release_slot(table, slot);

    if (stat_rc != 0) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_FILE_SIZE;
    } else {
        cpu->eax = (uint32_t)st.st_size;
        if (p_high != 0) {
            void *high_ptr = guest_memory_pointer(p_high, 4ULL, 1);
            if (!high_ptr) {
                *fault = p_high;
                return -1;
            }
            uint32_t high_val = (uint32_t)((uint64_t)st.st_size >> 32);
            memcpy(high_ptr, &high_val, 4);
        }
    }

    cpu->eip = ret_addr;
    cpu->esp += 12U;
    return 1;
}

/* --- GetFileAttributesA (argc 1, frame 8 bytes) --- */
static int handle_get_file_attributes_a(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, pn;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&pn, f + 4, 4);

    char win_path[GUEST_VFS_PATH_MAX];
    size_t k = 0;
    while (k < sizeof(win_path) - 1) {
        const char *ch_ptr = (const char *)guest_memory_pointer(pn + (uint32_t)k, 1ULL, 0);
        if (!ch_ptr) {
            *fault = pn + (uint32_t)k;
            return -1;
        }
        win_path[k] = *ch_ptr;
        if (win_path[k] == '\0') break;
        k++;
    }
    win_path[k] = '\0';

    char host_path[1024];
    int res = guest_vfs_resolve(&table->vfs, win_path, 0,
                                host_path, sizeof(host_path), NULL, 0);

    if (res != 0) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_FILE_NOT_FOUND, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_FILE_ATTRIBUTES;
    } else {
        struct stat st;
        if (stat(host_path, &st) != 0) {
            int err_rc = set_teb_last_error(cpu, GUEST_ERROR_FILE_NOT_FOUND, fault);
            if (err_rc) return err_rc;
            cpu->eax = GUEST_INVALID_FILE_ATTRIBUTES;
        } else {
            cpu->eax = S_ISDIR(st.st_mode) ? GUEST_FILE_ATTRIBUTE_DIRECTORY : GUEST_FILE_ATTRIBUTE_NORMAL;
        }
    }

    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* --- DeleteFileA (argc 1, frame 8 bytes) --- */
static int handle_delete_file_a(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, pn;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&pn, f + 4, 4);

    char win_path[GUEST_VFS_PATH_MAX];
    size_t k = 0;
    while (k < sizeof(win_path) - 1) {
        const char *ch_ptr = (const char *)guest_memory_pointer(pn + (uint32_t)k, 1ULL, 0);
        if (!ch_ptr) {
            *fault = pn + (uint32_t)k;
            return -1;
        }
        win_path[k] = *ch_ptr;
        if (win_path[k] == '\0') break;
        k++;
    }
    win_path[k] = '\0';

    char host_path[1024];
    int res = guest_vfs_resolve(&table->vfs, win_path, 1,
                                host_path, sizeof(host_path), NULL, 0);

    if (res != 0 || unlink(host_path) != 0) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_FILE_NOT_FOUND, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U; /* FALSE */
    } else {
        cpu->eax = 1U; /* TRUE */
    }

    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* --- FlushFileBuffers (argc 1, frame 8 bytes) --- */
static int handle_flush_file_buffers(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
    } else {
        fsync(slot->fd);
        release_slot(table, slot);
        cpu->eax = 1U;
    }

    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* --- SetEndOfFile (argc 1, frame 8 bytes) --- */
static int handle_set_end_of_file(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);

    GuestFileSlot *slot = retain_slot(table, hfile);
    if (!slot) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
    } else {
        pthread_mutex_lock(&slot->slot_lock);
        off_t cur = lseek(slot->fd, 0, SEEK_CUR);
        int tr_rc = (cur >= 0 && ftruncate(slot->fd, cur) == 0);
        pthread_mutex_unlock(&slot->slot_lock);
        release_slot(table, slot);
        cpu->eax = tr_rc ? 1U : 0U;
    }

    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* --- CreateDirectoryA (argc 2, frame 12 bytes) --- */
static int handle_create_directory_a(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, pn, sa;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&pn, f + 4, 4);
    memcpy(&sa, f + 8, 4);
    (void)sa;

    char win_path[GUEST_VFS_PATH_MAX];
    size_t k = 0;
    while (k < sizeof(win_path) - 1) {
        const char *ch_ptr = (const char *)guest_memory_pointer(pn + (uint32_t)k, 1ULL, 0);
        if (!ch_ptr) {
            *fault = pn + (uint32_t)k;
            return -1;
        }
        win_path[k] = *ch_ptr;
        if (win_path[k] == '\0') break;
        k++;
    }
    win_path[k] = '\0';

    char host_path[1024];
    int res = guest_vfs_resolve(&table->vfs, win_path, 1, host_path, sizeof(host_path), NULL, 0);
    if (res == -2) {
        set_teb_last_error(cpu, GUEST_ERROR_PATH_NOT_FOUND, fault);
        cpu->eax = 0U;
    } else {
        vfs_mkdir_parents(host_path);
        int m_rc = mkdir(host_path, 0755);
        if (m_rc == 0 || errno == EEXIST) {
            cpu->eax = 1U;
        } else {
            set_teb_last_error(cpu, GUEST_ERROR_ACCESS_DENIED, fault);
            cpu->eax = 0U;
        }
    }

    cpu->eip = ret_addr;
    cpu->esp += 12U;
    return 1;
}

/* --- GetOverlappedResult (argc 4, frame 20 bytes) --- */
static int handle_get_overlapped_result(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    (void)table;
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 20ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, hfile, ov, pnt, wait;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&hfile, f + 4, 4);
    memcpy(&ov, f + 8, 4);
    memcpy(&pnt, f + 12, 4);
    memcpy(&wait, f + 16, 4);
    (void)hfile; (void)wait;

    if (ov != 0 && pnt != 0) {
        const void *ov_ptr = guest_memory_pointer(ov, 8ULL, 0);
        if (!ov_ptr) {
            *fault = ov;
            return -1;
        }
        uint32_t bytes_transferred;
        memcpy(&bytes_transferred, (const uint8_t *)ov_ptr + 4, 4);

        void *pnt_ptr = guest_memory_pointer(pnt, 4ULL, 1);
        if (!pnt_ptr) {
            *fault = pnt;
            return -1;
        }
        memcpy(pnt_ptr, &bytes_transferred, 4);
    }

    cpu->eax = 1U;
    cpu->eip = ret_addr;
    cpu->esp += 20U;
    return 1;
}

/* --- HasOverlappedIoCompleted (argc 1, frame 8 bytes) --- */
static int handle_has_overlapped_io_completed(CPU *cpu, GuestFileTable *table, uint32_t *fault)
{
    (void)table;
    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_addr, ov;
    const uint8_t *f = (const uint8_t *)frame_ptr;
    memcpy(&ret_addr, f, 4);
    memcpy(&ov, f + 4, 4);

    uint32_t status = 0;
    if (ov != 0) {
        const void *ov_ptr = guest_memory_pointer(ov, 4ULL, 0);
        if (!ov_ptr) {
            *fault = ov;
            return -1;
        }
        memcpy(&status, ov_ptr, 4);
    }

    /* NTSTATUS: STATUS_PENDING is 0x00000103. If not pending, it has completed! */
    cpu->eax = (status != 0x00000103u) ? 1U : 0U;
    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}

/* =========================================================================
 * Dispatcher Hook: guest_file_import
 * ========================================================================= */
int guest_file_import(CPU *cpu, const GuestImport *imp, void *context, uint32_t *fault)
{
    if (!cpu || !imp || !fault || !imp->name || !imp->library) {
        return 0;
    }

    if (strcasecmp(imp->library, "KERNEL32.dll") != 0) {
        return 0;
    }

    GuestFileTable *table = (GuestFileTable *)context;
    if (!table || !table->initialized) {
        return 0;
    }

    if (strcmp(imp->name, "CreateFileA") == 0) {
        return handle_create_file_a(cpu, table, fault);
    }
    if (strcmp(imp->name, "ReadFile") == 0) {
        return handle_read_file(cpu, table, fault);
    }
    if (strcmp(imp->name, "WriteFile") == 0) {
        return handle_write_file(cpu, table, fault);
    }
    if (strcmp(imp->name, "SetFilePointer") == 0) {
        return handle_set_file_pointer(cpu, table, fault);
    }
    if (strcmp(imp->name, "CloseHandle") == 0) {
        return handle_close_handle(cpu, table, fault);
    }
    if (strcmp(imp->name, "GetFileSize") == 0) {
        return handle_get_file_size(cpu, table, fault);
    }
    if (strcmp(imp->name, "GetFileAttributesA") == 0) {
        return handle_get_file_attributes_a(cpu, table, fault);
    }
    if (strcmp(imp->name, "SetFileAttributesA") == 0) {
        /* Win32 SetFileAttributesA stub: argc 2, frame 12 bytes */
        const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
        if (!frame_ptr) { *fault = cpu->esp; return -1; }
        uint32_t ret_addr;
        memcpy(&ret_addr, frame_ptr, 4);
        cpu->eax = 1U;
        cpu->eip = ret_addr;
        cpu->esp += 12U;
        return 1;
    }
    if (strcmp(imp->name, "DeleteFileA") == 0) {
        return handle_delete_file_a(cpu, table, fault);
    }
    if (strcmp(imp->name, "FlushFileBuffers") == 0) {
        return handle_flush_file_buffers(cpu, table, fault);
    }
    if (strcmp(imp->name, "SetEndOfFile") == 0) {
        return handle_set_end_of_file(cpu, table, fault);
    }
    if (strcmp(imp->name, "CreateDirectoryA") == 0) {
        return handle_create_directory_a(cpu, table, fault);
    }
    if (strcmp(imp->name, "GetOverlappedResult") == 0) {
        return handle_get_overlapped_result(cpu, table, fault);
    }
    if (strcmp(imp->name, "HasOverlappedIoCompleted") == 0) {
        return handle_has_overlapped_io_completed(cpu, table, fault);
    }

    return 0;
}
