#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cpu.h"
#include "guest_memory.h"
#include "guest_startup.h"

#define GRANULE_SIZE 0x4000

#define PROT_NONE ((enum GuestMemoryProtection)0)
#define PROT_READ ((enum GuestMemoryProtection)1)
#define PROT_READ_WRITE ((enum GuestMemoryProtection)2)

#define REQUIRE_VM(expr) do { if ((expr) != 0) { fprintf(stderr, "FAIL VM setup line %d\n", __LINE__); abort(); } } while (0)

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

static int write_guest(uint32_t addr, const void *src, size_t len) {
    uint8_t *dst = (uint8_t *)guest_memory_pointer(addr, (uint64_t)len, 1);
    CHECK(dst != NULL);
    memcpy(dst, src, len);
    return 0;
}

static int read_guest(uint32_t addr, void *dst, size_t len) {
    const uint8_t *src = (const uint8_t *)guest_memory_pointer(addr, (uint64_t)len, 0);
    CHECK(src != NULL);
    memcpy(dst, src, len);
    return 0;
}

static void init_cpu_state(CPU *cpu, uint32_t esp, uint32_t eip, uint32_t fs_base) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0x11111111;
    cpu->ebx = 0x22222222;
    cpu->ecx = 0x33333333;
    cpu->edx = 0x44444444;
    cpu->esi = 0x55555555;
    cpu->edi = 0x66666666;
    cpu->ebp = 0x77777777;
    cpu->esp = esp;
    cpu->eip = eip;
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x00000000;
    eflags_set(cpu, 0x00000246);
}

static int verify_cpu_success(const CPU *actual, const CPU *snapshot, uint32_t expected_ret, uint32_t old_esp) {
    CPU expected = *snapshot;
    expected.eip = expected_ret;
    expected.esp = old_esp + 8;
    CHECK(memcmp(actual, &expected, sizeof(CPU)) == 0);
    CHECK(eflags_get((CPU *)actual) == eflags_get((CPU *)snapshot));
    return 0;
}

static int verify_cpu_unmodified(const CPU *actual, const CPU *snapshot) {
    CHECK(memcmp(actual, snapshot, sizeof(CPU)) == 0);
    CHECK(eflags_get((CPU *)actual) == eflags_get((CPU *)snapshot));
    return 0;
}

static int setup_call_frame(uint32_t esp, uint32_t ret_ip, uint32_t out_arg) {
    uint32_t frame[2];
    frame[0] = ret_ip;
    frame[1] = out_arg;
    return write_guest(esp, frame, sizeof(frame));
}

static int test_exact_68_extent_and_guards(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t out_addr = 0x20010;
    uint8_t prefill[68];
    uint8_t result[68];
    uint8_t g_before, g_after;
    uint32_t cb;

    memset(prefill, 0xCC, sizeof(prefill));
    cb = 0x12345678;
    memcpy(prefill, &cb, sizeof(cb));

    CHECK(write_guest(out_addr, prefill, sizeof(prefill)) == 0);
    g_before = 0x5A;
    g_after = 0xA5;
    CHECK(write_guest(out_addr - 1, &g_before, 1) == 0);
    CHECK(write_guest(out_addr + 68, &g_after, 1) == 0);

    CHECK(setup_call_frame(0x10000, 0x00401000, out_addr) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(fault == 0xDEADBEEF);

    g_before = 0;
    g_after = 0;
    CHECK(read_guest(out_addr - 1, &g_before, 1) == 0);
    CHECK(read_guest(out_addr + 68, &g_after, 1) == 0);
    CHECK(g_before == 0x5A);
    CHECK(g_after == 0xA5);

    CHECK(read_guest(out_addr, result, sizeof(result)) == 0);
    memcpy(&cb, result, sizeof(cb));
    CHECK(cb == 68);
    for (size_t i = 4; i < 68; i++) {
        CHECK(result[i] == 0);
    }

    CHECK(verify_cpu_success(&cpu, &snapshot, 0x00401000, 0x10000) == 0);
    return 0;
}

static int test_teb_and_last_error_not_probed(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "kernel32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t out_addr = 0x20080;
    uint32_t last_error_sentinel = 0xCAFEBABE;
    uint32_t read_back = 0;

    CHECK(write_guest(0x30034, &last_error_sentinel, sizeof(last_error_sentinel)) == 0);
    CHECK(setup_call_frame(0x10020, 0x00402000, out_addr) == 0);
    init_cpu_state(&cpu, 0x10020, 0x00400010, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(read_guest(0x30034, &read_back, sizeof(read_back)) == 0);
    CHECK(read_back == 0xCAFEBABE);
    CHECK(verify_cpu_success(&cpu, &snapshot, 0x00402000, 0x10020) == 0);

    CHECK(setup_call_frame(0x10020, 0x00403000, out_addr) == 0);
    init_cpu_state(&cpu, 0x10020, 0x00400020, 0xE0000000);
    snapshot = cpu;

    rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(verify_cpu_success(&cpu, &snapshot, 0x00403000, 0x10020) == 0);
    CHECK(cpu.fs_base == 0xE0000000);
    return 0;
}

static int test_unaligned_callframe_and_output(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "Kernel32.DLL", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t esp = 0x10003;
    uint32_t out_addr = 0x20005;
    uint8_t g_before = 0x33, g_after = 0x44;
    uint8_t res[68];
    uint32_t cb;

    CHECK(write_guest(out_addr - 1, &g_before, 1) == 0);
    CHECK(write_guest(out_addr + 68, &g_after, 1) == 0);
    CHECK(setup_call_frame(esp, 0x00405566, out_addr) == 0);

    init_cpu_state(&cpu, esp, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == 1);

    g_before = 0;
    g_after = 0;
    CHECK(read_guest(out_addr - 1, &g_before, 1) == 0);
    CHECK(read_guest(out_addr + 68, &g_after, 1) == 0);
    CHECK(g_before == 0x33);
    CHECK(g_after == 0x44);

    CHECK(read_guest(out_addr, res, sizeof(res)) == 0);
    memcpy(&cb, res, sizeof(cb));
    CHECK(cb == 68);
    for (size_t i = 4; i < 68; i++) {
        CHECK(res[i] == 0);
    }

    CHECK(verify_cpu_success(&cpu, &snapshot, 0x00405566, esp) == 0);
    return 0;
}

static int test_output_aliases_callframe(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t esp = 0x10100;
    uint32_t out_addr = esp;
    uint8_t res[68];
    uint32_t cb;

    CHECK(setup_call_frame(esp, 0x00407788, out_addr) == 0);
    init_cpu_state(&cpu, esp, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(read_guest(out_addr, res, sizeof(res)) == 0);
    memcpy(&cb, res, sizeof(cb));
    CHECK(cb == 68);
    for (size_t i = 4; i < 68; i++) {
        CHECK(res[i] == 0);
    }

    CHECK(verify_cpu_success(&cpu, &snapshot, 0x00407788, esp) == 0);
    return 0;
}

static int test_unknown_inputs_and_null_host(void) {
    CPU cpu, snapshot;
    GuestImport imp_valid = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    GuestImport imp_bad_lib = { .iat = 0x1000, .library = "USER32.dll", .name = "GetStartupInfoA" };
    GuestImport imp_bad_name = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "getstartupinfoa" };
    GuestImport imp_other_name = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoW" };
    GuestImport imp_null_lib = { .iat = 0x1000, .library = NULL, .name = "GetStartupInfoA" };
    GuestImport imp_null_name = { .iat = 0x1000, .library = "KERNEL32.dll", .name = NULL };
    uint32_t fault = 0xAA55AA55;

    CHECK(setup_call_frame(0x10000, 0x00401000, 0x20000) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    CHECK(guest_startup_import(NULL, &imp_valid, &fault) == 0);
    CHECK(guest_startup_import(&cpu, NULL, &fault) == 0);
    CHECK(guest_startup_import(&cpu, &imp_valid, NULL) == 0);
    CHECK(guest_startup_import(&cpu, &imp_null_lib, &fault) == 0);
    CHECK(guest_startup_import(&cpu, &imp_null_name, &fault) == 0);
    CHECK(guest_startup_import(&cpu, &imp_bad_lib, &fault) == 0);
    CHECK(guest_startup_import(&cpu, &imp_bad_name, &fault) == 0);
    CHECK(guest_startup_import(&cpu, &imp_other_name, &fault) == 0);

    CHECK(fault == 0xAA55AA55);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);
    return 0;
}

static int test_null_output_even_if_page0_mapped(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint8_t zero_sentinel[68];
    uint8_t check_buf[68];

    REQUIRE_VM(guest_memory_commit(0x00000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x00000, GRANULE_SIZE, PROT_READ_WRITE));
    CHECK(guest_memory_pointer(0x00000, GRANULE_SIZE, 1) != NULL);

    memset(zero_sentinel, 0x7A, sizeof(zero_sentinel));
    CHECK(write_guest(0x00000, zero_sentinel, sizeof(zero_sentinel)) == 0);

    CHECK(setup_call_frame(0x10000, 0x00401000, 0x00000000) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0x00000000);

    CHECK(read_guest(0x00000, check_buf, sizeof(check_buf)) == 0);
    CHECK(memcmp(zero_sentinel, check_buf, sizeof(check_buf)) == 0);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);
    return 0;
}

static int test_fault_bad_stack_frame(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault;

    init_cpu_state(&cpu, 0x80000000, 0x00400000, 0x30000);
    snapshot = cpu;
    fault = 0x11111111;
    CHECK(guest_startup_import(&cpu, &imp, &fault) == -1);
    CHECK(fault == 0x80000000);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);

    init_cpu_state(&cpu, 0xFFFFFFFC, 0x00400000, 0x30000);
    snapshot = cpu;
    fault = 0x22222222;
    CHECK(guest_startup_import(&cpu, &imp, &fault) == -1);
    CHECK(fault == 0xFFFFFFFC);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);

    REQUIRE_VM(guest_memory_commit(0x40000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x40000, GRANULE_SIZE, PROT_NONE));
    init_cpu_state(&cpu, 0x40000, 0x00400000, 0x30000);
    snapshot = cpu;
    fault = 0x33333333;
    CHECK(guest_startup_import(&cpu, &imp, &fault) == -1);
    CHECK(fault == 0x40000);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);
    return 0;
}

static int test_fault_read_only_output(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t ro_addr = 0x28000;
    uint8_t init_pat[68];
    uint8_t read_back[68];

    REQUIRE_VM(guest_memory_commit(ro_addr, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(ro_addr, GRANULE_SIZE, PROT_READ_WRITE));
    memset(init_pat, 0x77, sizeof(init_pat));
    CHECK(write_guest(ro_addr, init_pat, sizeof(init_pat)) == 0);
    REQUIRE_VM(guest_memory_protect(ro_addr, GRANULE_SIZE, PROT_READ));
    CHECK(setup_call_frame(0x10000, 0x00401000, ro_addr) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == -1);
    CHECK(fault == ro_addr);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);

    REQUIRE_VM(guest_memory_protect(ro_addr, GRANULE_SIZE, PROT_READ_WRITE));
    CHECK(read_guest(ro_addr, read_back, sizeof(read_back)) == 0);
    CHECK(memcmp(init_pat, read_back, sizeof(read_back)) == 0);
    return 0;
}

static int test_fault_cross_granule_partial_unmapped(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t out_base = 0x54000 - 32;
    uint8_t pat[32];
    uint8_t read_back[32];

    REQUIRE_VM(guest_memory_commit(0x50000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x50000, GRANULE_SIZE, PROT_READ_WRITE));
    memset(pat, 0x66, sizeof(pat));
    CHECK(write_guest(out_base, pat, sizeof(pat)) == 0);

    CHECK(setup_call_frame(0x10000, 0x00401000, out_base) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == -1);
    CHECK(fault == out_base);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);

    CHECK(read_guest(out_base, read_back, sizeof(read_back)) == 0);
    CHECK(memcmp(pat, read_back, sizeof(read_back)) == 0);
    return 0;
}

static int test_fault_cross_granule_rw_to_ro(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t out_base = 0x64000 - 32;
    uint8_t pat[32];
    uint8_t read_back[32];

    REQUIRE_VM(guest_memory_commit(0x60000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x60000, GRANULE_SIZE, PROT_READ_WRITE));
    REQUIRE_VM(guest_memory_commit(0x64000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x64000, GRANULE_SIZE, PROT_READ));
    memset(pat, 0x44, sizeof(pat));
    CHECK(write_guest(out_base, pat, sizeof(pat)) == 0);

    CHECK(setup_call_frame(0x10000, 0x00401000, out_base) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == -1);
    CHECK(fault == out_base);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);

    CHECK(read_guest(out_base, read_back, sizeof(read_back)) == 0);
    CHECK(memcmp(pat, read_back, sizeof(read_back)) == 0);
    return 0;
}

static int test_fault_top_4gib_overflow_output(void) {
    CPU cpu, snapshot;
    GuestImport imp = { .iat = 0x1000, .library = "KERNEL32.dll", .name = "GetStartupInfoA" };
    uint32_t fault = 0xDEADBEEF;
    uint32_t out_base = 0xFFFFFFE0;

    CHECK(setup_call_frame(0x10000, 0x00401000, out_base) == 0);
    init_cpu_state(&cpu, 0x10000, 0x00400000, 0x30000);
    snapshot = cpu;

    int rc = guest_startup_import(&cpu, &imp, &fault);
    CHECK(rc == -1);
    CHECK(fault == out_base);
    CHECK(verify_cpu_unmodified(&cpu, &snapshot) == 0);
    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0);

    REQUIRE_VM(guest_memory_commit(0x10000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x10000, GRANULE_SIZE, PROT_READ_WRITE));
    REQUIRE_VM(guest_memory_commit(0x20000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x20000, GRANULE_SIZE, PROT_READ_WRITE));
    REQUIRE_VM(guest_memory_commit(0x30000, GRANULE_SIZE));
    REQUIRE_VM(guest_memory_protect(0x30000, GRANULE_SIZE, PROT_READ_WRITE));
    CHECK(test_exact_68_extent_and_guards() == 0);
    CHECK(test_teb_and_last_error_not_probed() == 0);
    CHECK(test_unaligned_callframe_and_output() == 0);
    CHECK(test_output_aliases_callframe() == 0);
    CHECK(test_unknown_inputs_and_null_host() == 0);
    CHECK(test_null_output_even_if_page0_mapped() == 0);
    CHECK(test_fault_bad_stack_frame() == 0);
    CHECK(test_fault_read_only_output() == 0);
    CHECK(test_fault_cross_granule_partial_unmapped() == 0);
    CHECK(test_fault_cross_granule_rw_to_ro() == 0);
    CHECK(test_fault_top_4gib_overflow_output() == 0);

    CHECK(guest_memory_shutdown() == 0);
    printf("PASS | guest startup contracts\n");
    return 0;
}
