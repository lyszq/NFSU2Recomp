#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "cpu.h"
#include "guest_memory.h"
#include "guest_windows.h"
#include "guest_execution.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define STACK_ADDR  0x10000u
#define BUFFER_ADDR 0x20000u
#define TEB_ADDR    0x30000u
#define RET_ADDR    0x00401234u
#define SENTINEL    0xDEADBEEFu

static void put32(uint32_t addr, uint32_t val) {
    memcpy(g_mem + addr, &val, 4);
}

static uint32_t get32(uint32_t addr) {
    uint32_t val;
    memcpy(&val, g_mem + addr, 4);
    return val;
}

static void put64(uint32_t addr, uint64_t val) {
    memcpy(g_mem + addr, &val, 8);
}

static uint64_t get64(uint32_t addr) {
    uint64_t val;
    memcpy(&val, g_mem + addr, 8);
    return val;
}

static CPU make_test_cpu(uint32_t esp, uint32_t ret_ip) {
    CPU c = {0};
    c.esp = esp;
    c.fs_base = TEB_ADDR;
    c.gs_base = TEB_ADDR;
    c.eax = 0xAAAAAAAAu;
    c.ebx = 0xBBBBBBBBu;
    c.ecx = 0xCCCCCCCCu;
    c.edx = 0xDDDDDDDDu;
    c.esi = 0x11111111u;
    c.edi = 0x22222222u;
    c.ebp = 0x33333333u;
    c.eip = 0x99999999u;
    eflags_set(&c, 0xCD5u);

    put32(esp, ret_ip);
    put32(TEB_ADDR + 0x20, 100u); /* Existing guest process identity (PID) */
    put32(TEB_ADDR + 0x24, 1u);   /* Existing guest thread identity (TID) */
    put32(TEB_ADDR + 0x34, 999u); /* Initial LastError to verify preservation */
    return c;
}

static void caller_stub(CPU *c) {
    guest_execution_step(c, 0x401000u);
    guest_execution_call(c, GUEST_IMPORT_BASE);
    guest_execution_step(c, RET_ADDR);
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_ADDR, 0x10000u) == 0);
    CHECK(guest_memory_commit(BUFFER_ADDR, 0x10000u) == 0);
    CHECK(guest_memory_commit(TEB_ADDR, 0x10000u) == 0);

    GuestWindows windows = {.image_base = 0x00400000u};
    uint32_t fault = 0;

    const GuestImport api_get_system_time = {
        .iat = 0x007830c0u,
        .library = "KERNEL32.dll",
        .name = "GetSystemTimeAsFileTime"
    };

    const GuestImport api_get_current_process_id = {
        .iat = 0x007830c4u,
        .library = "KERNEL32.dll",
        .name = "GetCurrentProcessId"
    };

    const GuestImport api_get_tick_count = {
        .iat = 0x007830c8u,
        .library = "KERNEL32.dll",
        .name = "GetTickCount"
    };

    const GuestImport api_query_perf_counter = {
        .iat = 0x007830ccu,
        .library = "KERNEL32.dll",
        .name = "QueryPerformanceCounter"
    };

    /* =========================================================================
     * 1. GetSystemTimeAsFileTime API Test Suite
     * WINAPI void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
     * - stdcall stack popping: 1 arg (4 bytes) + return ip (4 bytes) = 8 bytes
     * - writes 8 bytes (FILETIME: 100-ns intervals since 1601 UTC) to memory
     * - verifies memory fault when pointer is null or unmapped
     * - preserves LastError on success
     * ========================================================================= */
    uint64_t initial_filetime = 0;
    {
        /* Test 1.1: Standard valid invocation */
        put64(BUFFER_ADDR, UINT64_C(0xDEADBEEFCAFEBABE));
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        CPU expected = c;

        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 8u); /* 8 bytes total popped */
        CHECK(c.eip == RET_ADDR);

        /* Verify 8 bytes written and represent a non-zero UTC timestamp */
        initial_filetime = get64(BUFFER_ADDR);
        CHECK(initial_filetime != UINT64_C(0xDEADBEEFCAFEBABE));
        CHECK(initial_filetime > UINT64_C(0x01A0000000000000)); /* Post-2000 UTC FILETIME */

        /* Preservation of registers (void function), flags, and LastError */
        expected.esp = STACK_ADDR + 8u;
        expected.eip = RET_ADDR;
        expected.eax = c.eax;
        CHECK(memcmp(&c, &expected, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 1.2: Monotonicity / non-zero timestamp advancement across calls */
        put64(BUFFER_ADDR + 8, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR + 8);
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == 1);
        uint64_t second_filetime = get64(BUFFER_ADDR + 8);
        CHECK(second_filetime >= initial_filetime);
    }

    {
        /* Test 1.3: Memory fault when pointer is null */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0u); /* NULL lpSystemTimeAsFileTime */
        CPU before = c;
        fault = 0xCCCCCCCCu;
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 1.4: Memory fault when pointer is unmapped */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0x50000000u); /* Uncommitted address */
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 1.5: Partial unmapped memory fault (buffer wraps past 4 GiB) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0xFFFFFFFCu);
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == -1);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 1.6: Stack pointer boundary wrap near 4 GiB */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.esp = 0xFFFFFFFCu;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFCu);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 1.7: Unmapped stack memory fault */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.esp = 0x50000000u;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_system_time, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 1.8: Context fallback (NULL windows context) */
        put64(BUFFER_ADDR, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        int rc = guest_windows_import(&c, &api_get_system_time, NULL, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(c.eip == RET_ADDR);
        CHECK(get64(BUFFER_ADDR) > UINT64_C(0x01A0000000000000));
    }

    /* =========================================================================
     * 2. GetCurrentProcessId API Test Suite
     * WINAPI DWORD GetCurrentProcessId(void)
     * - 0 args: pops 4 bytes return ip
     * - returns TEB+0x20 PID in EAX (100)
     * - verifies TEB unmapped fault handling
     * - preserves LastError
     * ========================================================================= */
    {
        /* Test 2.1: Standard valid invocation returning default PID (100) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(TEB_ADDR + 0x20, 100u);
        CPU expected = c;

        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 4u); /* 0 args -> 4 bytes popped */
        CHECK(c.eip == RET_ADDR);
        CHECK(c.eax == 100u); /* PID from TEB+0x20 */

        /* Preservation of registers, flags, and LastError */
        expected.eax = 100u;
        expected.esp = STACK_ADDR + 4u;
        expected.eip = RET_ADDR;
        CHECK(memcmp(&c, &expected, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 2.2: Dynamic PID reflection from TEB+0x20 */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(TEB_ADDR + 0x20, 0x12345678u);
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0x12345678u);
        CHECK(c.esp == STACK_ADDR + 4u);
        put32(TEB_ADDR + 0x20, 100u); /* Restore standard PID */
    }

    {
        /* Test 2.3: Zero PID in TEB handling */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(TEB_ADDR + 0x20, 0u);
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -2); /* Invalid thread environment block state */
        CHECK(fault == TEB_ADDR + 0x20u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
        put32(TEB_ADDR + 0x20, 100u);
    }

    {
        /* Test 2.4: TEB unmapped fault handling (uncommitted fs_base) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.fs_base = 0x50000000u;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0x50000020u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 2.5: Zero fs_base fault handling */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.fs_base = 0u;
        CPU before = c;
        fault = 0xCCCCCCCCu;
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -2);
        CHECK(fault == 0u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 2.6: fs_base 32-bit address overflow wrap */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.fs_base = UINT32_MAX - 0x10u;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == UINT32_MAX);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 2.7: Stack memory fault handling */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.esp = 0x50000000u;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);

        c.esp = 0xFFFFFFFEu;
        before = c;
        fault = 0;
        rc = guest_windows_import(&c, &api_get_current_process_id, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFEu);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 2.8: Context fallback (NULL windows context) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        int rc = guest_windows_import(&c, &api_get_current_process_id, NULL, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 100u);
        CHECK(c.esp == STACK_ADDR + 4u);
    }

    /* =========================================================================
     * 3. GetTickCount API Test Suite
     * WINAPI DWORD GetTickCount(void)
     * - 0 args: pops 4 bytes return ip
     * - returns monotonic milliseconds in EAX
     * - preserves LastError
     * ========================================================================= */
    uint32_t initial_tick = 0;
    {
        /* Test 3.1: Standard valid invocation */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        CPU expected = c;

        int rc = guest_windows_import(&c, &api_get_tick_count, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 4u); /* 0 args -> 4 bytes popped */
        CHECK(c.eip == RET_ADDR);
        initial_tick = c.eax;

        /* Preservation of registers, flags, and LastError */
        expected.eax = initial_tick;
        expected.esp = STACK_ADDR + 4u;
        expected.eip = RET_ADDR;
        CHECK(memcmp(&c, &expected, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 3.2: Monotonicity across sequential calls */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        int rc = guest_windows_import(&c, &api_get_tick_count, &windows, &fault);
        CHECK(rc == 1);
        uint32_t second_tick = c.eax;
        CHECK(second_tick >= initial_tick);
    }

    {
        /* Test 3.3: Stack memory fault handling */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.esp = 0x50000000u;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_get_tick_count, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);

        c.esp = 0xFFFFFFFEu;
        before = c;
        fault = 0;
        rc = guest_windows_import(&c, &api_get_tick_count, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFEu);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 3.4: Context fallback (NULL windows context) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        int rc = guest_windows_import(&c, &api_get_tick_count, NULL, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 4u);
    }

    /* =========================================================================
     * 4. QueryPerformanceCounter API Test Suite
     * WINAPI BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
     * - stdcall stack popping: 1 arg (4 bytes) + return ip (4 bytes) = 8 bytes
     * - writes 8 bytes (LARGE_INTEGER: 64-bit performance count) to memory
     * - returns 1 (BOOL) in EAX
     * - verifies memory fault when pointer is null or unmapped
     * - preserves LastError
     * ========================================================================= */
    uint64_t initial_qpc = 0;
    {
        /* Test 4.1: Standard valid invocation */
        put64(BUFFER_ADDR, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        CPU expected = c;

        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 8u); /* 8 bytes total popped */
        CHECK(c.eip == RET_ADDR);
        CHECK(c.eax == 1u); /* Returns 1 (BOOL TRUE) in EAX */

        initial_qpc = get64(BUFFER_ADDR);
        CHECK(initial_qpc > 0);

        /* Preservation of registers, flags, and LastError */
        expected.eax = 1u;
        expected.esp = STACK_ADDR + 8u;
        expected.eip = RET_ADDR;
        CHECK(memcmp(&c, &expected, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 4.2: Monotonicity across sequential calls */
        put64(BUFFER_ADDR + 8, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR + 8);
        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 1u);
        uint64_t second_qpc = get64(BUFFER_ADDR + 8);
        CHECK(second_qpc >= initial_qpc);
    }

    {
        /* Test 4.3: Memory fault when pointer is null */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0u); /* NULL lpPerformanceCount */
        CPU before = c;
        fault = 0xCCCCCCCCu;
        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 4.4: Memory fault when pointer is unmapped */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0x50000000u); /* Uncommitted address */
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    {
        /* Test 4.5: Partial unmapped memory fault (buffer wraps past 4 GiB) */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, 0xFFFFFFFCu);
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == -1);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 4.6: Stack pointer boundary wrap / unmapped memory fault */
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        c.esp = 0xFFFFFFFCu;
        CPU before = c;
        fault = 0;
        int rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFCu);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);

        c.esp = 0x50000000u;
        before = c;
        fault = 0;
        rc = guest_windows_import(&c, &api_query_perf_counter, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 4.7: Context fallback (NULL windows context) */
        put64(BUFFER_ADDR, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        int rc = guest_windows_import(&c, &api_query_perf_counter, NULL, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 1u);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(get64(BUFFER_ADDR) > 0);
    }

    /* =========================================================================
     * 5. Common Protocol & Filtering Tests
     * - Case-insensitive library matching
     * - Unrelated library rejection
     * - Unrelated API name rejection
     * ========================================================================= */
    {
        /* Test 5.1: Case-insensitive library matching */
        const GuestImport mixed_case_api = {
            .iat = 0x007830c8u,
            .library = "kErNeL32.DlL",
            .name = "GetTickCount"
        };
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        int rc = guest_windows_import(&c, &mixed_case_api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.esp == STACK_ADDR + 4u);
    }

    {
        /* Test 5.2: Unrelated library rejection */
        const GuestImport user32_api = {
            .iat = 0x007830c8u,
            .library = "USER32.dll",
            .name = "GetTickCount"
        };
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        CPU before = c;
        int rc = guest_windows_import(&c, &user32_api, &windows, &fault);
        CHECK(rc == 0); /* Unhandled */
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    {
        /* Test 5.3: Unrelated API rejection */
        const GuestImport unknown_api = {
            .iat = 0x007830c8u,
            .library = "KERNEL32.dll",
            .name = "NonExistentTimeApi"
        };
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        CPU before = c;
        int rc = guest_windows_import(&c, &unknown_api, &windows, &fault);
        CHECK(rc == 0); /* Unhandled */
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
    }

    /* =========================================================================
     * 6. Execution Harness Integration Tests (guest_execution_run)
     * ========================================================================= */
    {
        /* Test 6.1: Harness dispatch for GetSystemTimeAsFileTime */
        const uint32_t addresses[] = {0x401000u};
        const GuestFunction functions[] = {caller_stub};
        GuestDispatch table = {0};
        CHECK(guest_dispatch_init(&table, 0x401000u, 0x1000, addresses, functions, 1) == 0);

        GuestExecutionConfig config = {
            .dispatch = &table,
            .imports = &api_get_system_time,
            .import_count = 1,
            .instruction_budget = 10,
            .depth_limit = 4,
            .timeout_ns = 1000000000,
            .import_handler = guest_windows_import,
            .import_context = &windows,
        };

        put64(BUFFER_ADDR, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        GuestExecutionResult result;
        int rc = guest_execution_run(&config, &c, 0x401000u, &result);
        CHECK(rc == 0);
        CHECK(result.stop == GUEST_STOP_RETURN);
        CHECK(result.imports_handled == 1);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(get64(BUFFER_ADDR) > UINT64_C(0x01A0000000000000));

        guest_dispatch_destroy(&table);
    }

    {
        /* Test 6.2: Harness dispatch for GetCurrentProcessId */
        const uint32_t addresses[] = {0x401000u};
        const GuestFunction functions[] = {caller_stub};
        GuestDispatch table = {0};
        CHECK(guest_dispatch_init(&table, 0x401000u, 0x1000, addresses, functions, 1) == 0);

        GuestExecutionConfig config = {
            .dispatch = &table,
            .imports = &api_get_current_process_id,
            .import_count = 1,
            .instruction_budget = 10,
            .depth_limit = 4,
            .timeout_ns = 1000000000,
            .import_handler = guest_windows_import,
            .import_context = &windows,
        };

        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(TEB_ADDR + 0x20, 100u);
        GuestExecutionResult result;
        int rc = guest_execution_run(&config, &c, 0x401000u, &result);
        CHECK(rc == 0);
        CHECK(result.stop == GUEST_STOP_RETURN);
        CHECK(result.imports_handled == 1);
        CHECK(c.eax == 100u);
        CHECK(c.esp == STACK_ADDR + 4u);

        guest_dispatch_destroy(&table);
    }

    {
        /* Test 6.3: Harness dispatch for GetTickCount */
        const uint32_t addresses[] = {0x401000u};
        const GuestFunction functions[] = {caller_stub};
        GuestDispatch table = {0};
        CHECK(guest_dispatch_init(&table, 0x401000u, 0x1000, addresses, functions, 1) == 0);

        GuestExecutionConfig config = {
            .dispatch = &table,
            .imports = &api_get_tick_count,
            .import_count = 1,
            .instruction_budget = 10,
            .depth_limit = 4,
            .timeout_ns = 1000000000,
            .import_handler = guest_windows_import,
            .import_context = &windows,
        };

        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        GuestExecutionResult result;
        int rc = guest_execution_run(&config, &c, 0x401000u, &result);
        CHECK(rc == 0);
        CHECK(result.stop == GUEST_STOP_RETURN);
        CHECK(result.imports_handled == 1);
        CHECK(c.esp == STACK_ADDR + 4u);

        guest_dispatch_destroy(&table);
    }

    {
        /* Test 6.4: Harness dispatch for QueryPerformanceCounter */
        const uint32_t addresses[] = {0x401000u};
        const GuestFunction functions[] = {caller_stub};
        GuestDispatch table = {0};
        CHECK(guest_dispatch_init(&table, 0x401000u, 0x1000, addresses, functions, 1) == 0);

        GuestExecutionConfig config = {
            .dispatch = &table,
            .imports = &api_query_perf_counter,
            .import_count = 1,
            .instruction_budget = 10,
            .depth_limit = 4,
            .timeout_ns = 1000000000,
            .import_handler = guest_windows_import,
            .import_context = &windows,
        };

        put64(BUFFER_ADDR, 0);
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR);
        put32(STACK_ADDR + 4, BUFFER_ADDR);
        GuestExecutionResult result;
        int rc = guest_execution_run(&config, &c, 0x401000u, &result);
        CHECK(rc == 0);
        CHECK(result.stop == GUEST_STOP_RETURN);
        CHECK(result.imports_handled == 1);
        CHECK(c.eax == 1u);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(get64(BUFFER_ADDR) > 0);

        guest_dispatch_destroy(&table);
    }

    CHECK(guest_memory_shutdown() == 0);
    puts("PASS | Guest Windows Time/Identity/QPC contracts | stdcall + return values + TEB PID + monotonicity + LastError preserved + memory safety");
    return 0;
}
