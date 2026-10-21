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
    CHECK(rc == 0 || rc == -3); /* -3 because file doesn't exist at dummy root yet */
    CHECK(strcmp(canon_rel, "global/globalb.lzc") == 0);

    /* Relative with mixed slashes and dot */
    rc = guest_vfs_resolve(&vfs, ".\\CARS/350Z\\GEOMETRY.BIN", 0, host_path, sizeof(host_path), canon_rel, sizeof(canon_rel));
    CHECK(strcmp(canon_rel, "cars/350z/geometry.bin") == 0);

    /* Traversal security check: must be rejected with -2 */
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

/* 4. Test Win32 Guest Imports: CreateFileA, ReadFile, SetFilePointer, GetFileSize, CloseHandle */
static int test_win32_api_imports(void) {
    const char *rroot = "/tmp/nfsu2_test_read";
    const char *wroot = "/tmp/nfsu2_test_write";
    setup_test_fs(rroot, wroot);

    GuestFileTable table;
    CHECK(guest_file_init(&table, rroot, wroot) == 0);
    CHECK(guest_file_index_roots(&table) == 0);

    /* Allocate virtual guest memory pages for stack, TEB, buffer */
    CHECK(guest_memory_commit(0x00000, 0x100000) == 0);

    CPU cpu;
    init_cpu(&cpu);
    uint32_t fault = 0;

    /* Write path string into guest memory at 0x50000 */
    const char *test_path = "GLOBAL\\GLOBALB.LZC";
    void *path_mem = guest_memory_pointer(0x50000u, strlen(test_path) + 1, 1);
    CHECK(path_mem != NULL);
    strcpy((char *)path_mem, test_path);

    /* --- 4a. CreateFileA (OPEN_EXISTING, GENERIC_READ) --- */
    write_u32(STACK_ADDR + 0, RET_ADDR);       /* return address */
    write_u32(STACK_ADDR + 4, 0x50000u);       /* lpFileName */
    write_u32(STACK_ADDR + 8, GUEST_GENERIC_READ); /* dwDesiredAccess */
    write_u32(STACK_ADDR + 12, 1);             /* dwShareMode */
    write_u32(STACK_ADDR + 16, 0);             /* lpSecurityAttributes */
    write_u32(STACK_ADDR + 20, GUEST_OPEN_EXISTING); /* dwCreationDisposition */
    write_u32(STACK_ADDR + 24, 0x80);          /* dwFlagsAndAttributes (NORMAL) */
    write_u32(STACK_ADDR + 28, 0);             /* hTemplateFile */

    GuestImport imp_create = {0, "KERNEL32.dll", "CreateFileA"};
    int rc = guest_file_import(&cpu, &imp_create, &table, &fault);
    CHECK(rc == 1);
    uint32_t hFile = cpu.eax;
    CHECK(hFile == GUEST_FILE_HANDLE_BASE + 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == STACK_ADDR + 32);

    /* --- 4b. GetFileSize --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, 0); /* lpFileSizeHigh = NULL */

    GuestImport imp_size = {0, "KERNEL32.dll", "GetFileSize"};
    rc = guest_file_import(&cpu, &imp_size, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == strlen("LZC_MAGIC_HEADER_NFSU2_ASSET_DATA_12345678"));
    CHECK(cpu.esp == STACK_ADDR + 12);

    /* --- 4c. ReadFile --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, BUF_ADDR);      /* lpBuffer */
    write_u32(STACK_ADDR + 12, 16);           /* nNumberOfBytesToRead */
    write_u32(STACK_ADDR + 16, 0x60000u);     /* lpNumberOfBytesRead */
    write_u32(STACK_ADDR + 20, 0);            /* lpOverlapped = NULL */

    GuestImport imp_read = {0, "KERNEL32.dll", "ReadFile"};
    rc = guest_file_import(&cpu, &imp_read, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(read_u32(0x60000u) == 16);

    char read_buf[17] = {0};
    memcpy(read_buf, guest_memory_pointer(BUF_ADDR, 16, 0), 16);
    CHECK(memcmp(read_buf, "LZC_MAGIC_HEADER", 16) == 0);
    CHECK(cpu.esp == STACK_ADDR + 24);

    /* --- 4d. SetFilePointer --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    write_u32(STACK_ADDR + 8, 4);             /* lDistanceToMove = +4 */
    write_u32(STACK_ADDR + 12, 0);            /* lpDistanceToMoveHigh = NULL */
    write_u32(STACK_ADDR + 16, GUEST_FILE_BEGIN); /* dwMoveMethod = FILE_BEGIN */

    GuestImport imp_seek = {0, "KERNEL32.dll", "SetFilePointer"};
    rc = guest_file_import(&cpu, &imp_seek, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 4);
    CHECK(cpu.esp == STACK_ADDR + 20);

    /* --- 4e. Overlapped ReadFile --- */
    uint32_t ov_addr = 0x70000u;
    write_u32(ov_addr + 0, 0xFFFFFFFFu); /* Internal */
    write_u32(ov_addr + 4, 0xFFFFFFFFu); /* InternalHigh */
    write_u32(ov_addr + 8, 10);          /* Offset low = 10 */
    write_u32(ov_addr + 12, 0);          /* Offset high = 0 */
    write_u32(ov_addr + 16, 0);          /* hEvent = 0 */

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
    CHECK(read_u32(ov_addr + 4) == 6);  /* bytes read */
    CHECK(read_u32(0x60000u) == 6);

    memset(read_buf, 0, sizeof(read_buf));
    memcpy(read_buf, guest_memory_pointer(BUF_ADDR, 6, 0), 6);
    CHECK(memcmp(read_buf, "HEADER", 6) == 0);

    /* --- 4f. CloseHandle --- */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);

    GuestImport imp_close = {0, "KERNEL32.dll", "CloseHandle"};
    rc = guest_file_import(&cpu, &imp_close, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(cpu.esp == STACK_ADDR + 8);

    /* Re-reading closed handle must fail with ERROR_INVALID_HANDLE */
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, hFile);
    rc = guest_file_import(&cpu, &imp_size, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_INVALID_FILE_SIZE);
    CHECK(read_u32(TEB_ADDR + 0x34) == GUEST_ERROR_INVALID_HANDLE);

    /* --- 4g. Non-existent file open must fail with ERROR_FILE_NOT_FOUND --- */
    const char *missing_path = "NON_EXISTENT_FILE.BIN";
    strcpy((char *)path_mem, missing_path);
    cpu.esp = STACK_ADDR;
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0x50000u);
    write_u32(STACK_ADDR + 8, GUEST_GENERIC_READ);
    write_u32(STACK_ADDR + 12, 1);
    write_u32(STACK_ADDR + 16, 0);
    write_u32(STACK_ADDR + 20, GUEST_OPEN_EXISTING);
    write_u32(STACK_ADDR + 24, 0x80);
    write_u32(STACK_ADDR + 28, 0);

    rc = guest_file_import(&cpu, &imp_create, &table, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_INVALID_HANDLE_VALUE);
    CHECK(read_u32(TEB_ADDR + 0x34) == GUEST_ERROR_FILE_NOT_FOUND);

    guest_file_cleanup(&table);
    printf("PASS: test_win32_api_imports\n");
    return 0;
}

int main(void) {
    printf("=== Starting NFSU2 Guest File & VFS Unit Tests ===\n");
    if (test_path_normalization() != 0) return 1;
    if (test_case_map_cache() != 0) return 1;
    if (test_dual_root_and_copy_up() != 0) return 1;
    if (test_win32_api_imports() != 0) return 1;
    printf("=== All NFSU2 Guest File & VFS Unit Tests PASSED ===\n");
    return 0;
}
