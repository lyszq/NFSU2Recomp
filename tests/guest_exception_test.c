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

#define STACK_ADDR 0x10000u
#define TEB_ADDR   0x30000u
#define RET_ADDR   0x00401234u
#define SENTINEL   0xDEADBEEFu

static void put32(uint32_t addr, uint32_t val) {
    memcpy(g_mem + addr, &val, 4);
}

static uint32_t get32(uint32_t addr) {
    uint32_t val;
    memcpy(&val, g_mem + addr, 4);
    return val;
}

static CPU make_test_cpu(uint32_t esp, uint32_t ret_ip, uint32_t filter_arg) {
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
    put32(esp + 4, filter_arg);
    put32(TEB_ADDR + 0x34, 999); /* Preserve LastError */
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
    CHECK(guest_memory_commit(TEB_ADDR, 0x10000u) == 0);

    GuestImport api = {
        .iat = 0x007830c0u,
        .library = "KERNEL32.dll",
        .name = "SetUnhandledExceptionFilter"
    };

    GuestWindows windows = {.image_base = 0x00400000u};
    uint32_t fault = 0;

    /* Test 1: Initial call with new filter address (0x00450000) returns 0 (NULL). */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00450000u);
        CPU expected = c;
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0u);
        CHECK(c.eip == RET_ADDR);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(windows.unhandled_exception_filter == 0x00450000u);

        /* Verify preservation of all other registers, flags, and LastError */
        expected.eax = 0u;
        expected.eip = RET_ADDR;
        expected.esp = STACK_ADDR + 8u;
        CHECK(memcmp(&c, &expected, sizeof(c)) == 0);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    /* Test 2: Second call with replacement filter (0x00460000) returns previous filter. */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00460000u);
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0x00450000u);
        CHECK(c.eip == RET_ADDR);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(windows.unhandled_exception_filter == 0x00460000u);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    /* Test 3: Clearing filter with NULL (0) returns previous filter. */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0u);
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0x00460000u);
        CHECK(c.eip == RET_ADDR);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(windows.unhandled_exception_filter == 0u);
        CHECK(get32(TEB_ADDR + 0x34) == 999u);
    }

    /* Test 4: Setting new filter after clear returns 0 (NULL). */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00470000u);
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0u);
        CHECK(c.eip == RET_ADDR);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(windows.unhandled_exception_filter == 0x00470000u);
    }

    /* Test 5: Stack memory boundary condition (stack pointer wrap near 4 GiB). */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00480000u);
        c.esp = 0xFFFFFFFCu; /* Only 4 bytes available before 32-bit wrap */
        CPU before = c;
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == -1); /* GUEST_STOP_MEMORY */
        CHECK(fault == 0xFFFFFFFCu);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(windows.unhandled_exception_filter == 0x00470000u); /* Filter unchanged */
    }

    /* Test 6: Unmapped stack memory fault. */
    {
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00480000u);
        c.esp = 0x50000000u; /* Uncommitted page */
        CPU before = c;
        int rc = guest_windows_import(&c, &api, &windows, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x50000000u);
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(windows.unhandled_exception_filter == 0x00470000u);
    }

    /* Test 7: Case-insensitive library matching. */
    {
        GuestImport mixed_case_api = {
            .iat = 0x007830c0u,
            .library = "kErNeL32.DlL",
            .name = "SetUnhandledExceptionFilter"
        };
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00480000u);
        int rc = guest_windows_import(&c, &mixed_case_api, &windows, &fault);
        CHECK(rc == 1);
        CHECK(c.eax == 0x00470000u);
        CHECK(windows.unhandled_exception_filter == 0x00480000u);
    }

    /* Test 8: Unrelated library / API not intercepted. */
    {
        GuestImport user32_api = {
            .iat = 0x007830c0u,
            .library = "USER32.dll",
            .name = "SetUnhandledExceptionFilter"
        };
        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00490000u);
        CPU before = c;
        int rc = guest_windows_import(&c, &user32_api, &windows, &fault);
        CHECK(rc == 0); /* Not handled */
        CHECK(memcmp(&c, &before, sizeof(c)) == 0);
        CHECK(windows.unhandled_exception_filter == 0x00480000u);
    }

    /* Test 9: Execution harness dispatch test (guest_execution_run). */
    {
        const uint32_t addresses[] = {0x401000u};
        const GuestFunction functions[] = {caller_stub};
        GuestDispatch table = {0};
        CHECK(guest_dispatch_init(&table, 0x401000u, 0x1000, addresses, functions, 1) == 0);

        GuestExecutionConfig config = {
            .dispatch = &table,
            .imports = &api,
            .import_count = 1,
            .instruction_budget = 10,
            .depth_limit = 4,
            .timeout_ns = 1000000000,
            .import_handler = guest_windows_import,
            .import_context = &windows,
        };

        CPU c = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00490000u);
        GuestExecutionResult result;
        int rc = guest_execution_run(&config, &c, 0x401000u, &result);
        CHECK(rc == 0);
        CHECK(result.stop == GUEST_STOP_RETURN);
        CHECK(result.imports_handled == 1);
        CHECK(c.eax == 0x00480000u);
        CHECK(c.esp == STACK_ADDR + 8u);
        CHECK(windows.unhandled_exception_filter == 0x00490000u);

        guest_dispatch_destroy(&table);
    }

    /* Test 10: Cleanup resets filter to 0. */
    {
        CHECK(guest_windows_cleanup(&windows) == 0);
        CHECK(windows.unhandled_exception_filter == 0u);
    }

    /* Test 11: Invocation with NULL context fallback. */
    {
        CPU c1 = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00500000u);
        int rc1 = guest_windows_import(&c1, &api, NULL, &fault);
        CHECK(rc1 == 1);
        CHECK(c1.eip == RET_ADDR);
        CHECK(c1.esp == STACK_ADDR + 8u);

        CPU c2 = make_test_cpu(STACK_ADDR, RET_ADDR, 0x00510000u);
        int rc2 = guest_windows_import(&c2, &api, NULL, &fault);
        CHECK(rc2 == 1);
        CHECK(c2.eax == 0x00500000u);
        CHECK(c2.eip == RET_ADDR);
        CHECK(c2.esp == STACK_ADDR + 8u);
    }

    CHECK(guest_memory_shutdown() == 0);
    puts("PASS | SetUnhandledExceptionFilter contract | stdcall + EAX prev filter + LastError preserved + memory safety + cleanup");
    return 0;
}
