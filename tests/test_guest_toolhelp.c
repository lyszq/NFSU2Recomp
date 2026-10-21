/*
 * Native Toolhelp32 Subsystem Comprehensive Test Suite
 * Validates snapshot lifecycle, Process32First/Next enumeration,
 * handle table reuse, LastError semantics, atomicity, and memory fault handling.
 */

#include "guest_toolhelp.h"
#include "cpu.h"
#include "guest_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

#define CHECK_MSG(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s (%s)\n", __FILE__, __LINE__, #cond, msg); \
        return 1; \
    } \
} while (0)

/* ========================================================================= */
/* Self-Contained Guest Memory Mock Harness                                  */
/* ========================================================================= */

uint8_t *g_mem = NULL;
uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];

#define MOCK_BLOCKS_MAX 16

typedef struct MockBlock {
    uint32_t base;
    uint32_t size;
    uint8_t *buffer;
    int writable;
    int active;
} MockBlock;

static MockBlock g_mock_blocks[MOCK_BLOCKS_MAX];

static void mock_memory_reset(void)
{
    for (int i = 0; i < MOCK_BLOCKS_MAX; i++) {
        if (g_mock_blocks[i].active && g_mock_blocks[i].buffer) {
            free(g_mock_blocks[i].buffer);
            g_mock_blocks[i].buffer = NULL;
        }
        g_mock_blocks[i].active = 0;
    }
}

static int mock_memory_commit(uint32_t base, uint32_t size, int writable)
{
    for (int i = 0; i < MOCK_BLOCKS_MAX; i++) {
        if (!g_mock_blocks[i].active) {
            g_mock_blocks[i].base = base;
            g_mock_blocks[i].size = size;
            g_mock_blocks[i].buffer = (uint8_t *)calloc(1, size);
            if (!g_mock_blocks[i].buffer) return -1;
            g_mock_blocks[i].writable = writable;
            g_mock_blocks[i].active = 1;
            return 0;
        }
    }
    return -1;
}

void *guest_memory_pointer(uint32_t address, uint64_t size, int write_access)
{
    if (size == 0 || (uint64_t)address + size > 0x100000000ULL) {
        return NULL;
    }
    const uint64_t end = (uint64_t)address + size;
    for (int i = 0; i < MOCK_BLOCKS_MAX; i++) {
        if (!g_mock_blocks[i].active) continue;
        const uint64_t b_base = g_mock_blocks[i].base;
        const uint64_t b_end = b_base + g_mock_blocks[i].size;
        if ((uint64_t)address >= b_base && end <= b_end) {
            if (write_access && !g_mock_blocks[i].writable) {
                return NULL;
            }
            return g_mock_blocks[i].buffer + ((uint64_t)address - b_base);
        }
    }
    return NULL;
}

/* ========================================================================= */
/* Test Constants and Helpers                                                */
/* ========================================================================= */

enum {
    STACK_ADDR         = 0x00018000u,
    STACK_SIZE         = 0x00004000u,
    TEB_ADDR           = 0x00020000u,
    TEB_SIZE           = 0x00004000u,
    BUFFER_ADDR        = 0x00040000u,
    BUFFER_SIZE        = 0x00004000u,
    UNCOMMITTED_ADDR   = 0x00080000u,
    LAST_ERROR_OFFSET  = 0x34u,
    RETURN_ADDR        = 0x00401234u,
    LAST_ERROR_SENTINEL = 0x13572468u
};

static const GuestImport API_CREATE_SNAPSHOT = { 0u, "KERNEL32.DLL", "CreateToolhelp32Snapshot" };
static const GuestImport API_PROCESS32_FIRST = { 0u, "KERNEL32.DLL", "Process32First" };
static const GuestImport API_PROCESS32_NEXT  = { 0u, "KERNEL32.DLL", "Process32Next" };
static const GuestImport API_CLOSE_HANDLE    = { 0u, "KERNEL32.DLL", "CloseHandle" };

static void init_cpu(CPU *cpu, uint32_t stack, uint32_t teb)
{
    memset(cpu, 0x5a, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = stack;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = 0x88888888u;
    cpu->fs_base = teb;
    cpu->gs_base = 0x99999999u;
    cpu->cf = 1;
    cpu->pf = 0;
    cpu->af = 1;
    cpu->zf = 0;
    cpu->sf = 1;
    cpu->of = 0;
    cpu->df = 1;
    cpu->id_flag = 0;
}

static uint32_t get_last_error(const CPU *cpu)
{
    uint32_t err = 0;
    void *ptr = guest_memory_pointer(cpu->fs_base + LAST_ERROR_OFFSET, sizeof(err), 0);
    if (ptr) {
        memcpy(&err, ptr, sizeof(err));
    }
    return err;
}

static void set_last_error(const CPU *cpu, uint32_t err)
{
    void *ptr = guest_memory_pointer(cpu->fs_base + LAST_ERROR_OFFSET, sizeof(err), 1);
    if (ptr) {
        memcpy(ptr, &err, sizeof(err));
    }
}

static int write_stack_frame(uint32_t stack, uint32_t ret_ip, uint32_t arg1, uint32_t arg2)
{
    uint32_t frame[3] = { ret_ip, arg1, arg2 };
    void *dst = guest_memory_pointer(stack, sizeof(frame), 1);
    if (!dst) return -1;
    memcpy(dst, frame, sizeof(frame));
    return 0;
}

static int write_close_frame(uint32_t stack, uint32_t ret_ip, uint32_t handle)
{
    uint32_t frame[2] = { ret_ip, handle };
    void *dst = guest_memory_pointer(stack, sizeof(frame), 1);
    if (!dst) return -1;
    memcpy(dst, frame, sizeof(frame));
    return 0;
}

/* ========================================================================= */
/* Test Cases                                                                */
/* ========================================================================= */

/* 1. test_toolhelp_init_cleanup: verifies zero initialization and reset */
static int test_toolhelp_init_cleanup(void)
{
    GuestToolhelpSet set;
    memset(&set, 0xCC, sizeof(set));

    guest_toolhelp_init(&set);
    CHECK(set.count == 0u);
    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; i++) {
        CHECK(set.snapshots[i].active == 0u);
        CHECK(set.snapshots[i].handle == 0u);
        CHECK(set.snapshots[i].process_id == 0u);
        CHECK(set.snapshots[i].iter_index == 0u);
    }

    /* Dirty the table */
    set.count = 4u;
    for (uint32_t i = 0; i < 4u; i++) {
        set.snapshots[i].active = 1u;
        set.snapshots[i].handle = GUEST_TOOLHELP_HANDLE_BASE + i + 1u;
        set.snapshots[i].process_id = 100u + i;
        set.snapshots[i].iter_index = 1u;
    }

    guest_toolhelp_cleanup(&set);
    CHECK(set.count == 0u);
    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; i++) {
        CHECK(set.snapshots[i].active == 0u);
        CHECK(set.snapshots[i].handle == 0u);
        CHECK(set.snapshots[i].process_id == 0u);
        CHECK(set.snapshots[i].iter_index == 0u);
    }

    puts("PASS [1/12]: test_toolhelp_init_cleanup");
    return 0;
}

/* 2. test_snapshot_create_success:
 *    verifies CreateToolhelp32Snapshot(2, nonzero PID) returns a valid handle in
 *    0x00D10001..0x00D10008, advances ESP by 12, sets EAX=handle.
 */
static int test_snapshot_create_success(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    set_last_error(&cpu, LAST_ERROR_SENTINEL);

    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 1234u));
    before = cpu;

    uint32_t fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == 1);
    CHECK(fault == 0xdeadbeefu);

    const uint32_t expected_handle = GUEST_TOOLHELP_HANDLE_BASE + 1u;
    CHECK(cpu.eax == expected_handle);
    CHECK(cpu.eax >= 0x00D10001u && cpu.eax <= 0x00D10008u);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR);

    /* Verify callee-preserved registers */
    CHECK(cpu.ebx == before.ebx);
    CHECK(cpu.ebp == before.ebp);
    CHECK(cpu.esi == before.esi);
    CHECK(cpu.edi == before.edi);
    CHECK(cpu.fs_base == before.fs_base);
    CHECK(cpu.gs_base == before.gs_base);

    /* LastError should remain untouched on success */
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    /* Toolhelp state */
    CHECK(set.count == 1u);
    CHECK(set.snapshots[0].active == 1u);
    CHECK(set.snapshots[0].handle == expected_handle);
    CHECK(set.snapshots[0].process_id == 100u);
    CHECK(set.snapshots[0].iter_index == 0u);

    /* Also verify creating with TH32CS_SNAPPROCESS | TH32CS_INHERIT works */
    CHECK(!write_stack_frame(cpu.esp, RETURN_ADDR + 4u,
                             GUEST_TH32CS_SNAPPROCESS | GUEST_TH32CS_INHERIT, 5678u));
    before = cpu;
    rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_TOOLHELP_HANDLE_BASE + 2u);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR + 4u);
    CHECK(set.count == 2u);

    guest_toolhelp_cleanup(&set);
    puts("PASS [2/12]: test_snapshot_create_success");
    return 0;
}

/* 3. Unsupported snapshot requests remain unhandled and leave state untouched. */
static int test_snapshot_create_unsupported_flags(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    set_last_error(&cpu, LAST_ERROR_SENTINEL);

    const uint32_t unsupported_flags[] = {
        0u, 1u, 4u, 8u, 16u, 6u, 0x12345678u, GUEST_TH32CS_INHERIT
    };
    for (size_t i = 0; i < sizeof(unsupported_flags) / sizeof(unsupported_flags[0]); ++i) {
        CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + (uint32_t)(i * 4u),
                                 unsupported_flags[i], 0u));
        before = cpu;
        GuestToolhelpSet set_before = set;
        uint32_t fault = 0xdeadbeefu;
        int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
        CHECK(rc == 0);
        CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
        CHECK(!memcmp(&set, &set_before, sizeof(set)));
        CHECK(fault == 0xdeadbeefu);
        CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);
    }

    guest_toolhelp_cleanup(&set);
    puts("PASS [3/12]: test_snapshot_create_unsupported_flags");
    return 0;
}

/* 4. Corrupt host bookkeeping stops without changing CPU, guest memory, or table. */
static int test_corrupted_snapshot_state(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);
    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    set_last_error(&cpu, LAST_ERROR_SENTINEL);

    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 1234u));
    set.count = 1u; /* No active row: count disagrees with the slots. */
    before = cpu;
    GuestToolhelpSet set_before = set;
    uint32_t fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    CHECK(!memcmp(&set, &set_before, sizeof(set)));
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    /* Inactive rows must be entirely zeroed, not just marked inactive. */
    guest_toolhelp_init(&set);
    set.snapshots[0].process_id = 100u;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 4u,
                             GUEST_TH32CS_SNAPPROCESS, 0u));
    before = cpu;
    set_before = set;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    CHECK(!memcmp(&set, &set_before, sizeof(set)));
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    /* Active records must identify the fixed guest PID and reachable iterator state. */
    guest_toolhelp_init(&set);
    set.count = 1u;
    set.snapshots[0].active = 1u;
    set.snapshots[0].handle = GUEST_TOOLHELP_HANDLE_BASE + 1u;
    set.snapshots[0].process_id = 101u;
    set.snapshots[0].iter_index = 0u;
    uint32_t size = GUEST_PROCESSENTRY32_SIZE;
    void *size_pointer = guest_memory_pointer(BUFFER_ADDR, sizeof(size), 1);
    CHECK(size_pointer != NULL);
    memcpy(size_pointer, &size, sizeof(size));
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 8u,
                             GUEST_TOOLHELP_HANDLE_BASE + 1u, BUFFER_ADDR));
    before = cpu;
    set_before = set;
    uint8_t buffer_before[GUEST_PROCESSENTRY32_SIZE];
    const void *buffer_pointer = guest_memory_pointer(BUFFER_ADDR, sizeof(buffer_before), 0);
    CHECK(buffer_pointer != NULL);
    memcpy(buffer_before, buffer_pointer, sizeof(buffer_before));
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    CHECK(!memcmp(&set, &set_before, sizeof(set)));
    buffer_pointer = guest_memory_pointer(BUFFER_ADDR, sizeof(buffer_before), 0);
    CHECK(buffer_pointer != NULL);
    CHECK(!memcmp(buffer_before, buffer_pointer, sizeof(buffer_before)));
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    /* Foreign handles pass through before the malformed table is inspected. */
    set.count = 0u;
    set_before = set;
    CHECK(!write_close_frame(STACK_ADDR, RETURN_ADDR + 12u, 0x12345678u));
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
    CHECK(rc == 0);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    CHECK(!memcmp(&set, &set_before, sizeof(set)));
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    guest_toolhelp_cleanup(&set);
    puts("PASS [4/12]: test_corrupted_snapshot_state");
    return 0;
}

/* 5. test_snapshot_create_capacity_limit:
 *    creating 8 snapshots succeeds; the 9th returns -1 and sets LastError.
 */
static int test_snapshot_create_capacity_limit(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    uint32_t handles[GUEST_TOOLHELP_SNAPSHOT_LIMIT];

    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; i++) {
        set_last_error(&cpu, LAST_ERROR_SENTINEL);
        cpu.esp = STACK_ADDR;
        CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));

        uint32_t fault = 0xdeadbeefu;
        int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
        CHECK(rc == 1);
        CHECK(cpu.eax == GUEST_TOOLHELP_HANDLE_BASE + i + 1u);
        CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);
        CHECK(set.count == i + 1u);
        handles[i] = cpu.eax;
    }

    /* All 8 handles must be distinct */
    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; i++) {
        for (uint32_t j = i + 1; j < GUEST_TOOLHELP_SNAPSHOT_LIMIT; j++) {
            CHECK(handles[i] != handles[j]);
        }
    }

    /* The 9th attempt must fail */
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x10u, GUEST_TH32CS_SNAPPROCESS, 0u));
    CPU before = cpu;

    uint32_t fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_INVALID_HANDLE_VALUE);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR + 0x10u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_INSUFFICIENT_BUFFER);
    CHECK(set.count == GUEST_TOOLHELP_SNAPSHOT_LIMIT);

    guest_toolhelp_cleanup(&set);
    puts("PASS [5/12]: test_snapshot_create_capacity_limit");
    return 0;
}

/* 5. test_process32first_success:
 *    passing valid snapshot handle and buffer with dwSize = 296 writes exact
 *    PROCESSENTRY32 (dwSize=296, pid=100, threads=1, priority=8, szExeFile="SPEED2.EXE"),
 *    returns EAX=1, ESP+=12.
 */
static int test_process32first_success(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    /* Create snapshot first */
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));
    uint32_t fault = 0;
    CHECK(guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault) == 1);
    const uint32_t handle = cpu.eax;

    /* Prepare guest buffer with canary bytes and set dwSize = 296 */
    uint8_t *buf = (uint8_t *)guest_memory_pointer(BUFFER_ADDR, GUEST_PROCESSENTRY32_SIZE, 1);
    CHECK(buf != NULL);
    memset(buf, 0xAA, GUEST_PROCESSENTRY32_SIZE);
    const uint32_t initial_size = GUEST_PROCESSENTRY32_SIZE;
    memcpy(buf, &initial_size, sizeof(initial_size));

    /* Prepare Process32First call frame */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x20u, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    before = cpu;

    fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == 1);
    CHECK(fault == 0xdeadbeefu);
    CHECK(cpu.eax == 1u);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR + 0x20u);
    CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

    /* Verify PROCESSENTRY32 structure contents written into guest memory */
    GuestProcessEntry32 entry;
    memcpy(&entry, buf, sizeof(entry));

    CHECK(entry.dwSize == 296u);
    CHECK(entry.cntUsage == 0u);
    CHECK(entry.th32ProcessID == 100u);
    CHECK(entry.th32DefaultHeapID == 0u);
    CHECK(entry.th32ModuleID == 0u);
    CHECK(entry.cntThreads == 1u);
    CHECK(entry.th32ParentProcessID == 0u);
    CHECK(entry.pcPriClassBase == 8);
    CHECK(entry.dwFlags == 0u);
    CHECK(strcmp(entry.szExeFile, "SPEED2.EXE") == 0);

    /* Verify rest of szExeFile is null-padded */
    for (size_t i = strlen("SPEED2.EXE"); i < sizeof(entry.szExeFile); i++) {
        CHECK(entry.szExeFile[i] == 0);
    }

    /* Verify snapshot iter_index advanced to 1 */
    CHECK(set.snapshots[0].iter_index == 1u);

    guest_toolhelp_cleanup(&set);
    puts("PASS [6/12]: test_process32first_success");
    return 0;
}

/* 6. test_process32first_insufficient_buffer:
 *    passing buffer with dwSize = 100 returns EAX=0, sets LastError to 122 (GUEST_ERROR_INSUFFICIENT_BUFFER).
 */
static int test_process32first_insufficient_buffer(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));
    uint32_t fault = 0;
    CHECK(guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault) == 1);
    const uint32_t handle = cpu.eax;

    /* Prepare buffer with dwSize = 100 (< 296) */
    uint8_t *buf = (uint8_t *)guest_memory_pointer(BUFFER_ADDR, GUEST_PROCESSENTRY32_SIZE, 1);
    CHECK(buf != NULL);
    const uint32_t small_size = 100u;
    memcpy(buf, &small_size, sizeof(small_size));

    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x30u, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    before = cpu;

    fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0u);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR + 0x30u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_INSUFFICIENT_BUFFER);

    /* Snapshot iter_index should not have advanced */
    CHECK(set.snapshots[0].iter_index == 0u);

    guest_toolhelp_cleanup(&set);
    puts("PASS [7/12]: test_process32first_insufficient_buffer");
    return 0;
}

/* 7. test_process32first_invalid_handle:
 *    passing non-existent handle returns EAX=0, sets LastError to 6 (GUEST_ERROR_INVALID_HANDLE).
 */
static int test_process32first_invalid_handle(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    /* Snapshot table is empty. Try a variety of invalid handles */
    const uint32_t bad_handles[] = {
        0x00D10001u, /* valid range but inactive slot */
        0x00D10005u,
        0x00D10000u, /* below base */
        0x00D10009u, /* above limit */
        0x00900001u, /* file handle */
        0x12345678u,
        0xFFFFFFFFu
    };

    uint8_t *buf = (uint8_t *)guest_memory_pointer(BUFFER_ADDR, GUEST_PROCESSENTRY32_SIZE, 1);
    CHECK(buf != NULL);
    const uint32_t valid_size = GUEST_PROCESSENTRY32_SIZE;
    memcpy(buf, &valid_size, sizeof(valid_size));

    for (size_t i = 0; i < sizeof(bad_handles)/sizeof(bad_handles[0]); i++) {
        cpu.esp = STACK_ADDR;
        CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, bad_handles[i], BUFFER_ADDR));
        set_last_error(&cpu, LAST_ERROR_SENTINEL);
        before = cpu;

        uint32_t fault = 0xdeadbeefu;
        int rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
        CHECK(rc == 1);
        CHECK(cpu.eax == 0u);
        CHECK(cpu.esp == before.esp + 12u);
        CHECK(cpu.eip == RETURN_ADDR);
        CHECK(get_last_error(&cpu) == GUEST_ERROR_INVALID_HANDLE);
    }

    guest_toolhelp_cleanup(&set);
    puts("PASS [8/12]: test_process32first_invalid_handle");
    return 0;
}

/* 8. test_process32next_end_of_enumeration:
 *    after Process32First, calling Process32Next returns EAX=0, sets LastError to 18 (GUEST_ERROR_NO_MORE_FILES).
 */
static int test_process32next_end_of_enumeration(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    /* 1. Create snapshot */
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));
    uint32_t fault = 0;
    CHECK(guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault) == 1);
    const uint32_t handle = cpu.eax;

    /* 2. Process32First succeeds */
    uint8_t *buf = (uint8_t *)guest_memory_pointer(BUFFER_ADDR, GUEST_PROCESSENTRY32_SIZE, 1);
    CHECK(buf != NULL);
    const uint32_t valid_size = GUEST_PROCESSENTRY32_SIZE;
    memcpy(buf, &valid_size, sizeof(valid_size));

    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x40u, handle, BUFFER_ADDR));
    CHECK(guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault) == 1);
    CHECK(cpu.eax == 1u);
    CHECK(set.snapshots[0].iter_index == 1u);

    /* 3. Process32Next called -> end of list (only 1 process exists) */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x44u, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    before = cpu;

    fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_PROCESS32_NEXT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0u);
    CHECK(cpu.esp == before.esp + 12u);
    CHECK(cpu.eip == RETURN_ADDR + 0x44u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_NO_MORE_FILES);

    /* 4. Subsequent Process32Next call still returns ERROR_NO_MORE_FILES */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x48u, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_NEXT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_NO_MORE_FILES);

    /* 5. Process32First again on same snapshot resets iter_index to 0 and returns process again */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x4cu, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1u);
    CHECK(set.snapshots[0].iter_index == 1u);

    /* 6. Process32Next with insufficient buffer returns INSUFFICIENT_BUFFER */
    const uint32_t small_size = 50u;
    memcpy(buf, &small_size, sizeof(small_size));
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x50u, handle, BUFFER_ADDR));
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_NEXT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_INSUFFICIENT_BUFFER);

    guest_toolhelp_cleanup(&set);
    puts("PASS [9/12]: test_process32next_end_of_enumeration");
    return 0;
}

/* 9. test_close_handle_success_and_reuse:
 *    closing a snapshot handle returns EAX=1; reclosing the same handle returns EAX=0 and
 *    sets LastError to 6; subsequent create re-allocates the freed slot.
 */
static int test_close_handle_success_and_reuse(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    /* Create 3 snapshots: slots 0, 1, 2 */
    uint32_t h[3];
    for (uint32_t i = 0; i < 3; i++) {
        cpu.esp = STACK_ADDR;
        CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));
        uint32_t fault = 0;
        CHECK(guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault) == 1);
        h[i] = cpu.eax;
        CHECK(h[i] == GUEST_TOOLHELP_HANDLE_BASE + i + 1u);
    }
    CHECK(set.count == 3u);

    /* 1. Close middle handle h[1] using direct API */
    uint32_t fault = 0xdeadbeefu;
    int rc = guest_toolhelp_close_handle(&cpu, &set, h[1], &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1u);
    CHECK(set.count == 2u);
    CHECK(set.snapshots[1].active == 0u);
    CHECK(set.snapshots[0].active == 1u);
    CHECK(set.snapshots[2].active == 1u);

    /* 2. Re-closing same handle h[1] fails with INVALID_HANDLE */
    set_last_error(&cpu, LAST_ERROR_SENTINEL);
    rc = guest_toolhelp_close_handle(&cpu, &set, h[1], &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0u);
    CHECK(get_last_error(&cpu) == GUEST_ERROR_INVALID_HANDLE);
    CHECK(set.count == 2u);

    /* 3. Close h[0] via import dispatch (CloseHandle) */
    cpu.esp = STACK_ADDR;
    CHECK(!write_close_frame(STACK_ADDR, RETURN_ADDR + 0x60u, h[0]));
    before = cpu;
    set_last_error(&cpu, LAST_ERROR_SENTINEL);

    rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1u);
    CHECK(cpu.esp == before.esp + 8u);
    CHECK(cpu.eip == RETURN_ADDR + 0x60u);
    CHECK(set.count == 1u);
    CHECK(set.snapshots[0].active == 0u);

    /* 4. Subsequent CreateToolhelp32Snapshot re-allocates the lowest freed slot (slot 0) */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x64u, GUEST_TH32CS_SNAPPROCESS, 0u));
    rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_TOOLHELP_HANDLE_BASE + 1u); /* slot 0 re-allocated */
    CHECK(set.count == 2u);
    CHECK(set.snapshots[0].active == 1u);

    /* 5. Next CreateToolhelp32Snapshot re-allocates slot 1 */
    cpu.esp = STACK_ADDR;
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR + 0x68u, GUEST_TH32CS_SNAPPROCESS, 0u));
    rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_TOOLHELP_HANDLE_BASE + 2u); /* slot 1 re-allocated */
    CHECK(set.count == 3u);
    CHECK(set.snapshots[1].active == 1u);

    guest_toolhelp_cleanup(&set);
    puts("PASS [10/12]: test_close_handle_success_and_reuse");
    return 0;
}

/* 10. test_close_handle_non_toolhelp:
 *     passing a handle like 0x00900001 returns 0 (indicating it's not a toolhelp handle
 *     and should pass through to other subsystems).
 */
static int test_close_handle_non_toolhelp(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    set_last_error(&cpu, LAST_ERROR_SENTINEL);

    const uint32_t foreign_handles[] = {
        0x00900001u, /* File handle */
        0x00900010u,
        0x00B10001u, /* User object handle (cursor/icon) */
        0x20000000u, /* Heap base */
        0x00000000u,
        0x00D10000u, /* Base boundary below valid handles */
        0x00D10009u, /* Boundary above limit */
        0xFFFFFFFFu
    };

    for (size_t i = 0; i < sizeof(foreign_handles)/sizeof(foreign_handles[0]); i++) {
        uint32_t fault = 0xdeadbeefu;

        /* Test direct function call */
        before = cpu;
        int rc = guest_toolhelp_close_handle(&cpu, &set, foreign_handles[i], &fault);
        CHECK(rc == 0);
        CHECK(fault == 0xdeadbeefu);
        CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
        CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);

        /* Test import dispatch */
        cpu.esp = STACK_ADDR;
        CHECK(!write_close_frame(STACK_ADDR, RETURN_ADDR, foreign_handles[i]));
        before = cpu;
        rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
        CHECK(rc == 0);
        CHECK(fault == 0xdeadbeefu);
        CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
        CHECK(get_last_error(&cpu) == LAST_ERROR_SENTINEL);
    }

    guest_toolhelp_cleanup(&set);
    puts("PASS [11/12]: test_close_handle_non_toolhelp");
    return 0;
}

/* 12. test_memory_faults:
 *     stack frame at uncommitted address returns -1 with correct *fault.
 */
static int test_memory_faults(void)
{
    GuestToolhelpSet set;
    guest_toolhelp_init(&set);

    CPU cpu, before;
    uint32_t fault = 0;

    /* A. CreateToolhelp32Snapshot with stack frame at uncommitted address */
    init_cpu(&cpu, UNCOMMITTED_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xdeadbeefu;
    int rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    CHECK(set.count == 0u);

    /* B. CreateToolhelp32Snapshot with stack frame overflowing 4GB boundary */
    init_cpu(&cpu, 0xFFFFFFF8u, TEB_ADDR);
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0xFFFFFFF8u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* C. Create a valid snapshot to test Process32First/Next faults */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, GUEST_TH32CS_SNAPPROCESS, 0u));
    CHECK(guest_toolhelp_import(&cpu, &API_CREATE_SNAPSHOT, &set, &fault) == 1);
    const uint32_t handle = cpu.eax;

    /* D. Process32First with uncommitted stack frame */
    init_cpu(&cpu, UNCOMMITTED_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* E. Process32First with valid stack frame but uncommitted lppe buffer */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, handle, UNCOMMITTED_ADDR));
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* F. Process32First with lppe buffer near 4GB boundary causing overflow */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, handle, 0xFFFFFF00u));
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_FIRST, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0xFFFFFF00u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* G. Process32Next with uncommitted stack frame */
    init_cpu(&cpu, UNCOMMITTED_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_NEXT, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* H. Process32Next with uncommitted lppe buffer */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CHECK(!write_stack_frame(STACK_ADDR, RETURN_ADDR, handle, UNCOMMITTED_ADDR));
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_PROCESS32_NEXT, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* I. CloseHandle import with uncommitted stack frame */
    init_cpu(&cpu, UNCOMMITTED_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));

    /* J. Setting LastError for an invalid in-range handle with an uncommitted TEB faults. */
    init_cpu(&cpu, STACK_ADDR, UNCOMMITTED_ADDR);
    CHECK(!write_close_frame(STACK_ADDR, RETURN_ADDR, GUEST_TOOLHELP_HANDLE_BASE + 8u));
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
    CHECK(rc == -1);
    CHECK(fault == UNCOMMITTED_ADDR + LAST_ERROR_OFFSET);

    /* K. fs_base == 0 returns -2 when reporting an invalid in-range handle. */
    init_cpu(&cpu, STACK_ADDR, 0u);
    CHECK(!write_close_frame(STACK_ADDR, RETURN_ADDR, GUEST_TOOLHELP_HANDLE_BASE + 8u));
    fault = 0xdeadbeefu;
    rc = guest_toolhelp_import(&cpu, &API_CLOSE_HANDLE, &set, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0u);

    guest_toolhelp_cleanup(&set);
    puts("PASS [12/12]: test_memory_faults");
    return 0;
}

/* ========================================================================= */
/* Main Runner                                                               */
/* ========================================================================= */

int main(void)
{
    printf("=== Running Native Toolhelp subsystem test suite ===\n");

    /* Commit guest memory regions */
    CHECK(!mock_memory_commit(STACK_ADDR, STACK_SIZE, 1));
    CHECK(!mock_memory_commit(TEB_ADDR, TEB_SIZE, 1));
    CHECK(!mock_memory_commit(BUFFER_ADDR, BUFFER_SIZE, 1));

    CHECK(!test_toolhelp_init_cleanup());
    CHECK(!test_snapshot_create_success());
    CHECK(!test_snapshot_create_unsupported_flags());
    CHECK(!test_corrupted_snapshot_state());
    CHECK(!test_snapshot_create_capacity_limit());
    CHECK(!test_process32first_success());
    CHECK(!test_process32first_insufficient_buffer());
    CHECK(!test_process32first_invalid_handle());
    CHECK(!test_process32next_end_of_enumeration());
    CHECK(!test_close_handle_success_and_reuse());
    CHECK(!test_close_handle_non_toolhelp());
    CHECK(!test_memory_faults());

    mock_memory_reset();

    printf("\nALL 12 NATIVE TOOLHELP TESTS PASSED!\n");
    return 0;
}
