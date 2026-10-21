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
#define TEB_ADDR    0x30000u
#define RET_ADDR    0x00401234u

static void put32(uint32_t addr, uint32_t val) {
    memcpy(g_mem + addr, &val, 4);
}

static uint32_t get32(uint32_t addr) {
    uint32_t val;
    memcpy(&val, g_mem + addr, 4);
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
    put32(TEB_ADDR + 0x20, 100u);
    put32(TEB_ADDR + 0x24, 1u);
    put32(TEB_ADDR + 0x34, 999u); /* Initial LastError */
    return c;
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_ADDR, 0x10000u) == 0);
    CHECK(guest_memory_commit(TEB_ADDR, 0x10000u) == 0);

    GuestWindows windows = {.image_base = 0x00400000u};
    uint32_t fault = 0;

    const GuestImport api_heap_create = {.iat = 0x101, .library = "KERNEL32.dll", .name = "HeapCreate"};
    const GuestImport api_heap_alloc = {.iat = 0x102, .library = "KERNEL32.dll", .name = "HeapAlloc"};
    const GuestImport api_heap_realloc = {.iat = 0x103, .library = "KERNEL32.dll", .name = "HeapReAlloc"};

    /* 1. Create a heap: HeapCreate(0, 4096, 65536) */
    uint32_t cur_esp = STACK_ADDR + 0x1000u;
    CPU cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, 0);     /* flOptions */
    put32(cur_esp + 8, 4096);  /* dwInitialSize */
    put32(cur_esp + 12, 65536);/* dwMaximumSize */

    int res = guest_windows_import(&cpu, &api_heap_create, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 16u);
    uint32_t heap_handle = cpu.eax;
    CHECK(heap_handle != 0);

    /* 2. Allocate initial block: HeapAlloc(heap_handle, 0, 16) */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0);   /* dwFlags */
    put32(cur_esp + 12, 16); /* dwBytes */

    res = guest_windows_import(&cpu, &api_heap_alloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 16u);
    uint32_t orig_ptr = cpu.eax;
    CHECK(orig_ptr != 0);

    /* Fill block with 0x42 */
    memset(g_mem + orig_ptr, 0x42, 16);

    /* Allocate second block to block in-place growth immediately following blk1 */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0);
    put32(cur_esp + 12, 16);
    res = guest_windows_import(&cpu, &api_heap_alloc, &windows, &fault);
    CHECK(res == 1);
    uint32_t block2 = cpu.eax;
    CHECK(block2 != 0);

    /* 3. HeapReAlloc with HEAP_REALLOC_IN_PLACE_ONLY (0x10) -> Should fail because block2 is adjacent */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0x10);  /* HEAP_REALLOC_IN_PLACE_ONLY */
    put32(cur_esp + 12, orig_ptr);
    put32(cur_esp + 16, 64);   /* expand to 64 bytes */

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 20u); /* 4 args + ret = 20 bytes popped */
    CHECK(cpu.eax == 0);             /* Failed */
    CHECK(get32(TEB_ADDR + 0x34) == 8); /* ERROR_NOT_ENOUGH_MEMORY */

    /* 4. HeapReAlloc normal with HEAP_ZERO_MEMORY (0x8) -> Relocates past block2 */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0x8);   /* HEAP_ZERO_MEMORY */
    put32(cur_esp + 12, orig_ptr);
    put32(cur_esp + 16, 64);   /* expand to 64 bytes */

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 20u);
    uint32_t relocated_ptr = cpu.eax;
    CHECK(relocated_ptr != 0);
    CHECK(relocated_ptr != orig_ptr);
    /* Verify preserved initial 16 bytes */
    for (int i = 0; i < 16; i++) {
        CHECK(g_mem[relocated_ptr + i] == 0x42);
    }
    /* Verify zeroed next 48 bytes */
    for (int i = 16; i < 64; i++) {
        CHECK(g_mem[relocated_ptr + i] == 0);
    }

    /* 5. In-place expansion on the relocated block (now free space after it) */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0x8);   /* HEAP_ZERO_MEMORY */
    put32(cur_esp + 12, relocated_ptr);
    put32(cur_esp + 16, 128);  /* expand to 128 bytes */

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 20u);
    CHECK(cpu.eax == relocated_ptr); /* In-place expansion! */
    for (int i = 0; i < 16; i++) {
        CHECK(g_mem[relocated_ptr + i] == 0x42);
    }
    for (int i = 16; i < 128; i++) {
        CHECK(g_mem[relocated_ptr + i] == 0);
    }

    /* 6. Shrink block to 8 bytes */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0);
    put32(cur_esp + 12, relocated_ptr);
    put32(cur_esp + 16, 8);

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == cur_esp + 20u);
    CHECK(cpu.eax == relocated_ptr);
    for (int i = 0; i < 8; i++) {
        CHECK(g_mem[relocated_ptr + i] == 0x42);
    }

    /* 7. Invalid parameters */
    /* Invalid pointer */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0);
    put32(cur_esp + 12, 0x55555555u); /* Invalid address */
    put32(cur_esp + 16, 32);

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 1);
    CHECK(cpu.eax == 0);
    CHECK(get32(TEB_ADDR + 0x34) == 87); /* ERROR_INVALID_PARAMETER */

    /* Unsupported flags (e.g. 0x4 HEAP_GENERATE_EXCEPTIONS) -> rejected before stack alter */
    cur_esp = STACK_ADDR + 0x1000u;
    cpu = make_test_cpu(cur_esp, RET_ADDR);
    put32(cur_esp + 4, heap_handle);
    put32(cur_esp + 8, 0x4); /* HEAP_GENERATE_EXCEPTIONS */
    put32(cur_esp + 12, relocated_ptr);
    put32(cur_esp + 16, 32);

    res = guest_windows_import(&cpu, &api_heap_realloc, &windows, &fault);
    CHECK(res == 0); /* Unhandled capability stops before modifying state */

    CHECK(guest_memory_shutdown() == 0);
    puts("PASS | HeapReAlloc | stdcall 20-byte popping, in-place, relocation, HEAP_ZERO_MEMORY, IN_PLACE_ONLY, LastError");
    return 0;
}
