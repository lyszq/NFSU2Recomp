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

/* --- Path Normalization & Traversal Sandbox Sanitization --- */
static int vfs_normalize_path(const char *win, char *out_canon, size_t out_sz)
{
    if (!win || !out_canon || out_sz == 0) return -1;

    const char *p = win;
    /* Skip drive letter e.g. "C:" or "D:" */
    if (p[0] && p[1] == ':') {
        p += 2;
    }

    /* Skip leading separators */
    while (*p == '\\' || *p == '/') {
        p++;
    }

    /* Skip virtual "NFSU2" root prefix if present */
    if (!strncasecmp(p, "NFSU2", 5) && (p[5] == '\\' || p[5] == '/' || p[5] == '\0')) {
        p += 5;
        while (*p == '\\' || *p == '/') {
            p++;
        }
    }

    /* Component stack for canonical path */
    char components[32][64];
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
            /* Convert component to lowercase */
            size_t clen = strlen(tok);
            if (clen >= 64) clen = 63;
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
                                      uint8_t *out_root, char *out_disk_rel,
                                      int prefer_write)
{
    if (!vfs || !canon_key) return NULL;

    uint32_t hash = vfs_hash(canon_key);
    uint32_t idx = hash & (GUEST_VFS_HASH_BUCKETS - 1);

    GuestVFSNode *match = NULL;
    for (GuestVFSNode *n = vfs->buckets[idx]; n; n = n->next) {
        if (n->hash == hash && strcmp(n->canonical_key, canon_key) == 0) {
            if (prefer_write && n->root_id == GUEST_VFS_ROOT_WRITE) {
                if (out_root) *out_root = n->root_id;
                if (out_disk_rel) snprintf(out_disk_rel, GUEST_VFS_PATH_MAX, "%s", n->disk_relpath);
                return n;
            }
            if (!match || n->root_id == GUEST_VFS_ROOT_WRITE) {
                match = n;
            }
        }
    }

    if (match) {
        if (out_root) *out_root = match->root_id;
        if (out_disk_rel) snprintf(out_disk_rel, GUEST_VFS_PATH_MAX, "%s", match->disk_relpath);
        return match;
    }

    return NULL;
}

static int vfs_cache_insert(GuestVFS *vfs, uint8_t root_id,
                            const char *canon_key, const char *disk_rel,
                            uint8_t is_dir)
{
    if (!vfs || !canon_key || !disk_rel) return -1;

    uint32_t hash = vfs_hash(canon_key);
    uint32_t idx = hash & (GUEST_VFS_HASH_BUCKETS - 1);

    /* Update existing if found */
    for (GuestVFSNode *n = vfs->buckets[idx]; n; n = n->next) {
        if (n->hash == hash && n->root_id == root_id && strcmp(n->canonical_key, canon_key) == 0) {
            snprintf(n->disk_relpath, sizeof(n->disk_relpath), "%s", disk_rel);
            n->is_dir = is_dir;
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
    node->is_dir = is_dir;

    node->next = vfs->buckets[idx];
    vfs->buckets[idx] = node;

    return 0;
}

/* --- Recursive Directory Indexer --- */
static void vfs_index_recursive(GuestVFS *vfs, const char *root_abs,
                                const char *rel_dir, uint8_t root_id)
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

        char item_rel[GUEST_VFS_PATH_MAX];
        if (rel_dir && rel_dir[0]) {
            snprintf(item_rel, sizeof(item_rel), "%s/%s", rel_dir, e->d_name);
        } else {
            snprintf(item_rel, sizeof(item_rel), "%s", e->d_name);
        }

        char canon[GUEST_VFS_PATH_MAX];
        if (vfs_normalize_path(item_rel, canon, sizeof(canon)) == 0) {
            uint8_t is_dir = (e->d_type == DT_DIR) ? 1 : 0;
            vfs_cache_insert(vfs, root_id, canon, item_rel, is_dir);

            if (is_dir) {
                vfs_index_recursive(vfs, root_abs, item_rel, root_id);
            }
        }
    }
    closedir(d);
}

/* --- Lazy On-Disk Case-Insensitive Step Search --- */
static int vfs_step_resolve(const char *root, const char *canon_path,
                            char *out_disk_rel, size_t out_sz)
{
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
        GuestVFSNode *cached = vfs_cache_lookup(vfs, canon, &root_id, disk_rel, 1);

        if (cached && root_id == GUEST_VFS_ROOT_WRITE) {
            snprintf(out_host_path, out_host_sz, "%s/%s", wroot, disk_rel);
        } else {
            /* Create new entry with canonical name or existing relative name */
            snprintf(out_host_path, out_host_sz, "%s/%s", wroot, canon);
            vfs_cache_insert(vfs, GUEST_VFS_ROOT_WRITE, canon, canon, 0);
        }
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* For read operations: check write_root first, then read_root */
    uint8_t root_id = 0;
    char disk_rel[GUEST_VFS_PATH_MAX];
    GuestVFSNode *cached = vfs_cache_lookup(vfs, canon, &root_id, disk_rel, 1);

    if (cached) {
        const char *base = (root_id == GUEST_VFS_ROOT_WRITE) ? vfs->write_root : vfs->read_root;
        snprintf(out_host_path, out_host_sz, "%s/%s", base, disk_rel);
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    /* Cache miss: check on disk in write_root, then read_root */
    if (vfs->write_root[0] && vfs_step_resolve(vfs->write_root, canon, disk_rel, sizeof(disk_rel))) {
        snprintf(out_host_path, out_host_sz, "%s/%s", vfs->write_root, disk_rel);
        vfs_cache_insert(vfs, GUEST_VFS_ROOT_WRITE, canon, disk_rel, 0);
        pthread_mutex_unlock(&vfs->lock);
        return 0;
    }

    if (vfs->read_root[0] && vfs_step_resolve(vfs->read_root, canon, disk_rel, sizeof(disk_rel))) {
        snprintf(out_host_path, out_host_sz, "%s/%s", vfs->read_root, disk_rel);
        vfs_cache_insert(vfs, GUEST_VFS_ROOT_READ, canon, disk_rel, 0);
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
            cached = vfs_cache_lookup(vfs, alt, &root_id, disk_rel, 1);
            if (cached) {
                const char *base = (root_id == GUEST_VFS_ROOT_WRITE) ? vfs->write_root : vfs->read_root;
                snprintf(out_host_path, out_host_sz, "%s/%s", base, disk_rel);
                pthread_mutex_unlock(&vfs->lock);
                return 0;
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

int guest_file_index_roots(GuestFileTable *table)
{
    if (!table || !table->initialized) return -1;

    pthread_mutex_lock(&table->vfs.lock);
    if (table->vfs.read_root[0]) {
        vfs_index_recursive(&table->vfs, table->vfs.read_root, "", GUEST_VFS_ROOT_READ);
    }
    if (table->vfs.write_root[0]) {
        vfs_index_recursive(&table->vfs, table->vfs.write_root, "", GUEST_VFS_ROOT_WRITE);
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
    }
    table->active_handles = 0;
    pthread_mutex_unlock(&table->lock);

    pthread_mutex_lock(&table->vfs.lock);
    if (table->vfs.node_pool) {
        free(table->vfs.node_pool);
        table->vfs.node_pool = NULL;
    }
    table->vfs.node_count = 0;
    table->vfs.node_capacity = 0;
    memset(table->vfs.buckets, 0, sizeof(table->vfs.buckets));
    pthread_mutex_unlock(&table->vfs.lock);

    pthread_mutex_destroy(&table->vfs.lock);
    pthread_mutex_destroy(&table->lock);
    table->initialized = 0;
    return 0;
}

/* --- Internal Handle Allocator & Lookup --- */
static uint32_t alloc_handle(GuestFileTable *table, int fd, int is_empty,
                             uint32_t access, uint32_t disp, const char *rel)
{
    pthread_mutex_lock(&table->lock);
    for (uint32_t i = 1; i < GUEST_FILE_HANDLE_MAX; i++) {
        if (!table->slots[i].in_use) {
            table->slots[i].in_use = 1;
            table->slots[i].fd = fd;
            table->slots[i].is_empty = is_empty;
            table->slots[i].access = access;
            table->slots[i].disposition = disp;
            if (rel) {
                snprintf(table->slots[i].rel_path, sizeof(table->slots[i].rel_path), "%s", rel);
            }
            table->active_handles++;
            pthread_mutex_unlock(&table->lock);
            return GUEST_FILE_HANDLE_BASE + i;
        }
    }
    pthread_mutex_unlock(&table->lock);
    return GUEST_INVALID_HANDLE_VALUE;
}

static GuestFileSlot *get_slot(GuestFileTable *table, uint32_t h)
{
    if (h < GUEST_FILE_HANDLE_BASE + 1 || h >= GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX) {
        return NULL;
    }
    uint32_t idx = h - GUEST_FILE_HANDLE_BASE;
    if (!table->slots[idx].in_use) {
        return NULL;
    }
    return &table->slots[idx];
}

static void free_handle(GuestFileTable *table, uint32_t h)
{
    if (h < GUEST_FILE_HANDLE_BASE + 1 || h >= GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX) {
        return;
    }
    uint32_t idx = h - GUEST_FILE_HANDLE_BASE;
    pthread_mutex_lock(&table->lock);
    if (table->slots[idx].in_use) {
        if (table->slots[idx].fd >= 0) {
            close(table->slots[idx].fd);
            table->slots[idx].fd = -1;
        }
        table->slots[idx].in_use = 0;
        table->slots[idx].is_empty = 0;
        if (table->active_handles > 0) {
            table->active_handles--;
        }
    }
    pthread_mutex_unlock(&table->lock);
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
    if (is_write && !(flags & O_TRUNC) && table->vfs.read_root[0] && table->vfs.write_root[0]) {
        struct stat st;
        if (stat(host_path, &st) != 0) {
            char src_path[1024];
            if (guest_vfs_resolve(&table->vfs, win_path, 0, src_path, sizeof(src_path), NULL, 0) == 0) {
                vfs_copy_file(src_path, host_path);
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

    GuestFileSlot *slot = get_slot(table, hfile);
    if (!slot || slot->fd < 0) {
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
            *fault = buf;
            return -1;
        }
    }

    ssize_t got = 0;

    /* Overlapped read branch */
    if (ov != 0) {
        void *ov_ptr = guest_memory_pointer(ov, 20ULL, 1);
        if (!ov_ptr) {
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
            /* Signal event if win32 event subsystem is linked */
            #if defined(__APPLE__) || defined(__linux__)
            extern void win32_signal_event(uint32_t) __attribute__((weak));
            if (win32_signal_event) win32_signal_event(hev);
            #endif
        }
    } else if (slot->is_empty) {
        got = 0; /* Instant EOF */
    } else {
        if (len > 0 && buf_ptr) {
            got = read(slot->fd, buf_ptr, (size_t)len);
            if (got < 0) got = 0;
        }
    }

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

    GuestFileSlot *slot = get_slot(table, hfile);
    if (!slot || slot->fd < 0) {
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
            *fault = dist_high_ptr;
            return -1;
        }
        int32_t high_val;
        memcpy(&high_val, high_ptr, 4);
        full_dist = (int64_t)(((uint64_t)(uint32_t)high_val << 32) | (uint64_t)dist_low);
    }

    off_t pos = lseek(slot->fd, (off_t)full_dist, whence);
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

    GuestFileSlot *slot = get_slot(table, hfile);
    if (!slot) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0U;
    } else {
        free_handle(table, hfile);
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

    GuestFileSlot *slot = get_slot(table, hfile);
    if (!slot || slot->fd < 0) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_FILE_SIZE;
        cpu->eip = ret_addr;
        cpu->esp += 12U;
        return 1;
    }

    if (slot->is_empty) {
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
    if (fstat(slot->fd, &st) != 0) {
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
    if (strcmp(imp->name, "SetFilePointer") == 0) {
        return handle_set_file_pointer(cpu, table, fault);
    }
    if (strcmp(imp->name, "CloseHandle") == 0) {
        return handle_close_handle(cpu, table, fault);
    }
    if (strcmp(imp->name, "GetFileSize") == 0) {
        return handle_get_file_size(cpu, table, fault);
    }

    return 0;
}
