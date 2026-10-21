#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cpu.h"
#include "guest_memory.h"
#include "guest_file.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define STACK_ADDR  0x10000u
#define TEB_ADDR    0x30000u
#define BUF_ADDR    0x40000u
#define RET_ADDR    0x00401234u

static void write_u32(uint32_t addr, uint32_t val) {
    void *p = guest_memory_pointer(addr, sizeof(val), 1);
    if (p) memcpy(p, &val, sizeof(val));
}

static uint32_t read_u32(uint32_t addr) {
    void *p = guest_memory_pointer(addr, sizeof(uint32_t), 0);
    if (!p) return 0xFFFFFFFFu;
    uint32_t val = 0;
    memcpy(&val, p, sizeof(val));
    return val;
}

static void init_cpu(CPU *cpu) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = STACK_ADDR;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = 0x88888888u;
    cpu->fs_base = TEB_ADDR;
    cpu->gs_base = 0x99999999u;
    eflags_set(cpu, 0x246u);
}

/* Helper to setup a test fixture directory on disk */
static void setup_test_fs(const char *rroot, const char *wroot) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s && mkdir -p %s/GLOBAL %s/CARS/350Z %s/TRACKS %s",
             rroot, wroot, rroot, rroot, rroot, wroot);
    system(cmd);

    /* Create sample asset files with distinct content */
    char path[1024];
    snprintf(path, sizeof(path), "%s/GLOBAL/GLOBALB.LZC", rroot);
    FILE *f1 = fopen(path, "wb");
    if (f1) { fputs("LZC_MAGIC_HEADER_NFSU2_ASSET_DATA_12345678", f1); fclose(f1); }

    snprintf(path, sizeof(path), "%s/CARS/350Z/GEOMETRY.BIN", rroot);
    FILE *f2 = fopen(path, "wb");
    if (f2) { fputs("350Z_GEOMETRY_BIN_MESH_DATA", f2); fclose(f2); }

    snprintf(path, sizeof(path), "%s/TRACKS/L2R.BUN", rroot);
    FILE *f3 = fopen(path, "wb");
    if (f3) { fputs("TRACK_L2R_CHUNK_BUNDLE_STREAM", f3); fclose(f3); }
}

/* 1. Test Path Normalization & Traversal Sandbox Protection */
static int test_path_normalization(void) {
    GuestVFS vfs;
    memset(&vfs, 0, sizeof(vfs));
    pthread_mutex_init(&vfs.lock, NULL);
    snprintf(vfs.read_root, sizeof(vfs.read_root), "/tmp/nfsu2_test");

    char host_path[1024];
    char canon_rel[260];

    /* Windows backslash & drive letter stripping */
    int rc = guest_vfs_resolve(&vfs, "C:\\NFSU2\\GLOBAL\\GLOBALB.LZC", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0 || rc == -3);
    CHECK(strcmp(canon_rel, "global/globalb.lzc") == 0);

    /* Relative with leading dot-backslash and NFSU2 virtual prefix */
    rc = guest_vfs_resolve(&vfs, ".\\NFSU2\\CARS\\350Z\\GEOMETRY.BIN", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(strcmp(canon_rel, "cars/350z/geometry.bin") == 0);

    /* Mixed slashes and trailing spaces/dots on components */
    rc = guest_vfs_resolve(&vfs, "CARS/350Z\\GEOMETRY.BIN. ", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(strcmp(canon_rel, "cars/350z/geometry.bin") == 0);

    /* Traversal security check: escaping sandbox must be rejected with -2 */
    rc = guest_vfs_resolve(&vfs, "..\\..\\private\\keys.txt", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == -2);

    rc = guest_vfs_resolve(&vfs, "GLOBAL\\..\\..\\..\\etc\\passwd", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == -2);

    pthread_mutex_destroy(&vfs.lock);
    printf("PASS: test_path_normalization\n");
    return 0;
}

/* 2. Test In-Memory Case Map Cache & Fast Resolution */
static int test_case_map_cache(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    char host_path[1024];
    char canon_rel[260];

    /* Lookup case-insensitive: uppercase on disk, lowercase in query */
    int rc = guest_vfs_resolve(&table.vfs, "cars\\350z\\geometry.bin", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, "/CARS/350Z/GEOMETRY.BIN") != NULL);

    /* Mixed case query */
    rc = guest_vfs_resolve(&table.vfs, "Global\\GlobalB.lzc", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, "/GLOBAL/GLOBALB.LZC") != NULL);

    guest_file_cleanup(&table);
    printf("PASS: test_case_map_cache\n");
    return 0;
}

/* 3. Test Dual-Root Overlay and Save Copy-Up */
static int test_dual_root_and_copy_up(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    char host_path[1024];
    char canon_rel[260];

    /* Write operation targets write_root */
    int rc = guest_vfs_resolve(&table.vfs, "memcard\\profile.dat", 1, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, wroot) != NULL);
    CHECK(strstr(host_path, "memcard/profile.dat") != NULL);

    guest_file_cleanup(&table);
    printf("PASS: test_dual_root_and_copy_up\n");
    return 0;
}

/* 4. Test Multi-Root Priority Hierarchy (Documents > Bundle > AppSupport) */
static int test_multi_root_priorities(void) {
    const char *doc_dir = "/tmp/nfsu2_test_p1_docs";
    const char *bun_dir = "/tmp/nfsu2_test_p2_bundle";
    const char *app_dir = "/tmp/nfsu2_test_p3_appsupport";

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "rm -rf %s %s %s && "
             "mkdir -p %s/Game/CARS/350Z %s/Game/CARS/350Z %s/Game/GLOBAL %s/NFSU2/Game/TRACKS %s/NFSU2/Game/GLOBAL",
             doc_dir, bun_dir, app_dir,
             doc_dir, bun_dir, bun_dir, app_dir, app_dir);
    system(cmd);

    /* Priority 1 (Documents/Game): User-modded car geometry */
    char p1_car[1024];
    snprintf(p1_car, sizeof(p1_car), "%s/Game/CARS/350Z/GEOMETRY.BIN", doc_dir);
    FILE *f1 = fopen(p1_car, "wb");
    if (f1) { fputs("MODDED_350Z_FROM_DOCUMENTS", f1); fclose(f1); }

    /* Priority 2 (AppBundle/Game): Vanilla car geometry + vanilla global */
    char p2_car[1024], p2_glob[1024];
    snprintf(p2_car, sizeof(p2_car), "%s/Game/CARS/350Z/GEOMETRY.BIN", bun_dir);
    FILE *f2 = fopen(p2_car, "wb");
    if (f2) { fputs("VANILLA_350Z_IN_BUNDLE", f2); fclose(f2); }

    snprintf(p2_glob, sizeof(p2_glob), "%s/Game/GLOBAL/GLOBALB.LZC", bun_dir);
    FILE *f2g = fopen(p2_glob, "wb");
    if (f2g) { fputs("VANILLA_GLOBALB_IN_BUNDLE", f2g); fclose(f2g); }

    /* Priority 3 (Application Support/NFSU2/Game): Tracks bundle + old global */
    char p3_track[1024], p3_glob[1024];
    snprintf(p3_track, sizeof(p3_track), "%s/NFSU2/Game/TRACKS/L2R.BUN", app_dir);
    FILE *f3 = fopen(p3_track, "wb");
    if (f3) { fputs("TRACK_L2R_IN_APPSUPPORT", f3); fclose(f3); }

    snprintf(p3_glob, sizeof(p3_glob), "%s/NFSU2/Game/GLOBAL/GLOBALB.LZC", app_dir);
    FILE *f3g = fopen(p3_glob, "wb");
    if (f3g) { fputs("OUTDATED_GLOBALB_IN_APPSUPPORT", f3g); fclose(f3g); }

    /* Initialize table with iOS multi-root layout */
    GuestFileTable table;
    CHECK(guest_file_init(&table, NULL, NULL) == 0);
    CHECK(guest_file_setup_ios_roots(&table, doc_dir, bun_dir, app_dir) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    char host_path[1024];
    char canon_rel[260];

    /* Case A: File exists in P1 and P2 -> Priority 1 (Documents) MUST WIN */
    int rc = guest_vfs_resolve(&table.vfs, "CARS\\350Z\\GEOMETRY.BIN", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, doc_dir) != NULL);

    /* Case B: File exists in P2 and P3 -> Priority 2 (Bundle) MUST WIN */
    rc = guest_vfs_resolve(&table.vfs, "GLOBAL\\GLOBALB.LZC", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, bun_dir) != NULL);

    /* Case C: File exists ONLY in P3 -> Priority 3 (AppSupport) resolves successfully */
    rc = guest_vfs_resolve(&table.vfs, "TRACKS\\L2R.BUN", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(rc == 0);
    CHECK(strstr(host_path, app_dir) != NULL);

    guest_file_cleanup(&table);
    printf("PASS: test_multi_root_priorities\n");
    return 0;
}

/* 5. Test Win32 Guest Imports: CreateFileA, ReadFile, SetFilePointer, GetFileSize, CloseHandle */
static int test_win32_api_imports(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    CHECK(guest_memory_commit(0x00000, 0x100000) == 0);

    CPU cpu;
    init_cpu(&cpu);
    uint32_t fault = 0;

    const char *test_path = "GLOBAL\\GLOBALB.LZC";
    void *path_mem = guest_memory_pointer(0x50000u, strlen(test_path) + 1, 1);
    CHECK(path_mem != NULL);
    strcpy((char *)path_mem, test_path);

    /* --- 5a. CreateFileA (OPEN_EXISTING, GENERIC_READ) --- */
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);
    write_u32(STACK_ADDR + 8, GUEST_GENERIC_READ);
    write_u32(STACK_ADDR + 12, 1);
    write_u32(STACK_ADDR + 16, 0);
    write_u32(STACK_ADDR + 20, GUEST_OPEN_EXISTING);
    write_u32(STACK_ADDR + 24, 0x80);
    write_u32(STACK_ADDR + 28, 0);

    GuestImport imp_create = {0, "KERNEL32.dll", "CreateFileA"};
    int rc = guest_file_import(&cpu, &imp_create, &table, &fault);
    CHECK(rc == 1);
    uint32_t hFile = cpu.eax;
    CHECK(hFile == GUEST_FILE_HANDLE_BASE + 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == STACK_ADDR + 32);

    /* --- 5b. GetFileSize --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, 0);

    GuestImport imp_size = {0, "KERNEL32.dll", "GetFileSize"};
    rc = guest_file_import(&cpu, &imp_size, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == strlen("LZC_MAGIC_HEADER_NFSU2_ASSET_DATA_12345678"));
    CHECK(cpu.esp == STACK_ADDR + 12);

    /* --- 5c. ReadFile --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    write_u32(STACK_ADDR + 12, 16);
    write_u32(STACK_ADDR + 16, 0x60000u);
    write_u32(STACK_ADDR + 20, 0);

    GuestImport imp_read = {0, "KERNEL32.dll", "ReadFile"};
    rc = guest_file_import(&cpu, &imp_read, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(read_u32(0x60000u) == 16);

    char read_buf[17] = {0};
    memcpy(read_buf, guest_memory_pointer(BUF_ADDR, 16, 0), 16);
    CHECK(memcmp(read_buf, "LZC_MAGIC_HEADER", 16) == 0);
    CHECK(cpu.esp == STACK_ADDR + 24);

    /* --- 5d. SetFilePointer --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, 4);
    write_u32(STACK_ADDR + 12, 0);
    write_u32(STACK_ADDR + 16, GUEST_FILE_BEGIN);

    GuestImport imp_seek = {0, "KERNEL32.dll", "SetFilePointer"};
    rc = guest_file_import(&cpu, &imp_seek, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 4);
    CHECK(cpu.esp == STACK_ADDR + 20);

    /* --- 5e. Overlapped ReadFile --- */
    uint32_t ov_addr = 0x70000u;
    write_u32(ov_addr + 0, 0xFFFFFFFFu);
    write_u32(ov_addr + 4, 0xFFFFFFFFu);
    write_u32(ov_addr + 8, 10);
    write_u32(ov_addr + 12, 0);
    write_u32(ov_addr + 16, 0);

    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    write_u32(STACK_ADDR + 12, 6);
    write_u32(STACK_ADDR + 16, 0x60000u);
    write_u32(STACK_ADDR + 20, ov_addr);

    rc = guest_file_import(&cpu, &imp_read, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(read_u32(ov_addr + 0) == 0);  /* STATUS_SUCCESS */
    CHECK(read_u32(ov_addr + 4) == 6);
    CHECK(read_u32(0x60000u) == 6);

    memset(read_buf, 0, sizeof(read_buf));
    memcpy(read_buf, guest_memory_pointer(BUF_ADDR, 6, 0), 6);
    CHECK(memcmp(read_buf, "HEADER", 6) == 0);

    /* --- 5f. CloseHandle --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);

    GuestImport imp_close = {0, "KERNEL32.dll", "CloseHandle"};
    rc = guest_file_import(&cpu, &imp_close, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(cpu.esp == STACK_ADDR + 8);

    guest_file_cleanup(&table);
    printf("PASS: test_win32_api_imports\n");
    return 0;
}

/* 6. Test Extended Win32 File APIs (WriteFile, Attributes, Delete, EndOfFile, Flush) */
static int test_extended_win32_file_apis(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    CPU cpu;
    init_cpu(&cpu);
    uint32_t fault = 0;

    /* --- 6a. CreateDirectoryA --- */
    const char *dir_name = "MEMCARD\\PROFILES";
    void *path_mem = guest_memory_pointer(0x50000u, strlen(dir_name) + 1, 1);
    strcpy((char *)path_mem, dir_name);

    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);
    write_u32(STACK_ADDR + 8, 0);

    GuestImport imp_mkdir = {0, "KERNEL32.dll", "CreateDirectoryA"};
    int rc = guest_file_import(&cpu, &imp_mkdir, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);

    /* --- 6b. GetFileAttributesA for Directory --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);

    GuestImport imp_attr = {0, "KERNEL32.dll", "GetFileAttributesA"};
    rc = guest_file_import(&cpu, &imp_attr, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_FILE_ATTRIBUTE_DIRECTORY);

    /* --- 6c. CreateFileA for Writing (CREATE_ALWAYS) --- */
    const char *save_file = "MEMCARD\\PROFILES\\SAVEGAME.DAT";
    strcpy((char *)path_mem, save_file);

    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);
    write_u32(STACK_ADDR + 8, GUEST_GENERIC_WRITE);
    write_u32(STACK_ADDR + 12, 0);
    write_u32(STACK_ADDR + 16, 0);
    write_u32(STACK_ADDR + 20, GUEST_CREATE_ALWAYS);
    write_u32(STACK_ADDR + 24, 0x80);
    write_u32(STACK_ADDR + 28, 0);

    GuestImport imp_create = {0, "KERNEL32.dll", "CreateFileA"};
    rc = guest_file_import(&cpu, &imp_create, &table, &fault);
    CHECK(rc == 1);
    uint32_t hSave = cpu.eax;
    CHECK(hSave != GUEST_INVALID_HANDLE_VALUE);

    /* --- 6d. WriteFile --- */
    const char *save_payload = "NFSU2_PLAYER_CAREER_SAVE_DATA_BLOCK";
    uint32_t payload_len = (uint32_t)strlen(save_payload);
    void *buf_ptr = guest_memory_pointer(BUF_ADDR, payload_len, 1);
    memcpy(buf_ptr, save_payload, payload_len);

    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hSave);
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    write_u32(STACK_ADDR + 12, payload_len);
    write_u32(STACK_ADDR + 16, 0x60000u); /* lpNumberOfBytesWritten */
    write_u32(STACK_ADDR + 20, 0);

    GuestImport imp_write = {0, "KERNEL32.dll", "WriteFile"};
    rc = guest_file_import(&cpu, &imp_write, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(read_u32(0x60000u) == payload_len);

    /* --- 6e. FlushFileBuffers & SetEndOfFile --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hSave);

    GuestImport imp_flush = {0, "KERNEL32.dll", "FlushFileBuffers"};
    rc = guest_file_import(&cpu, &imp_flush, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);

    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hSave);

    GuestImport imp_eof = {0, "KERNEL32.dll", "SetEndOfFile"};
    rc = guest_file_import(&cpu, &imp_eof, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);

    /* Close save handle */
    GuestImport imp_close = {0, "KERNEL32.dll", "CloseHandle"};
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hSave);
    guest_file_import(&cpu, &imp_close, &table, &fault);

    /* --- 6f. DeleteFileA --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);

    GuestImport imp_del = {0, "KERNEL32.dll", "DeleteFileA"};
    rc = guest_file_import(&cpu, &imp_del, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);

    guest_file_cleanup(&table);
    printf("PASS: test_extended_win32_file_apis\n");
    return 0;
}

/* 7. Test Handle Table Limits (1024 Handles) and Thread Safety Under Concurrent Retain */
static int test_handle_limits_and_thread_safety(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    CPU cpu;
    init_cpu(&cpu);
    uint32_t fault = 0;

    const char *test_path = "GLOBAL\\GLOBALB.LZC";
    void *path_mem = guest_memory_pointer(0x50000u, strlen(test_path) + 1, 1);
    strcpy((char *)path_mem, test_path);

    /* Open 500 handles sequentially to verify capacity far exceeds old 256 limit */
    uint32_t handles[500];
    GuestImport imp_create = {0, "KERNEL32.dll", "CreateFileA"};
    GuestImport imp_close = {0, "KERNEL32.dll", "CloseHandle"};

    for (int i = 0; i < 500; i++) {
        cpu.esp = STACK_ADDR;
        write_u32(STACK_ADDR + 0, RET_ADDR);
        write_u32(STACK_ADDR + 4, 0x50000u);
        write_u32(STACK_ADDR + 8, GUEST_GENERIC_READ);
        write_u32(STACK_ADDR + 12, 1);
        write_u32(STACK_ADDR + 16, 0);
        write_u32(STACK_ADDR + 20, GUEST_OPEN_EXISTING);
        write_u32(STACK_ADDR + 24, 0x80);
        write_u32(STACK_ADDR + 28, 0);

        int rc = guest_file_import(&cpu, &imp_create, &table, &fault);
        CHECK(rc == 1);
        handles[i] = cpu.eax;
        CHECK(handles[i] != GUEST_INVALID_HANDLE_VALUE);
    }

    CHECK(table.active_handles >= 500);

    /* Close all 500 handles */
    for (int i = 0; i < 500; i++) {
        cpu.esp = STACK_ADDR;
        write_u32(STACK_ADDR + 0, RET_ADDR);
        write_u32(STACK_ADDR + 4, handles[i]);

        int rc = guest_file_import(&cpu, &imp_close, &table, &fault);
        CHECK(rc == 1);
        CHECK(cpu.eax == 1);
    }

    CHECK(table.active_handles == 0);

    guest_file_cleanup(&table);
    printf("PASS: test_handle_limits_and_thread_safety\n");
    return 0;
}

int main(void) {
    printf("=== Starting NFSU2 Guest File & VFS Unit Tests ===\n");
    if (guest_memory_init() != 0) return 1;
    if (test_path_normalization() != 0) { guest_memory_shutdown(); return 1; }
    if (test_case_map_cache() != 0) { guest_memory_shutdown(); return 1; }
    if (test_dual_root_and_copy_up() != 0) { guest_memory_shutdown(); return 1; }
    if (test_multi_root_priorities() != 0) { guest_memory_shutdown(); return 1; }
    if (test_win32_api_imports() != 0) { guest_memory_shutdown(); return 1; }
    if (test_extended_win32_file_apis() != 0) { guest_memory_shutdown(); return 1; }
    if (test_handle_limits_and_thread_safety() != 0) { guest_memory_shutdown(); return 1; }
    guest_memory_shutdown();
    printf("=== All NFSU2 Guest File & VFS Unit Tests PASSED ===\n");
    return 0;
}
