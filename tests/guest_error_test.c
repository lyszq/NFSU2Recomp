#include "guest_error.h"
#include "guest_memory.h"
#include "cpu.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#define REQUIRE_VM(expr) do { if ((expr) != 0) { fprintf(stderr, "FAIL VM setup line %d\n", __LINE__); abort(); } } while (0)

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    if (fn() != 0) { \
        fprintf(stderr, "Test %s failed\n", #fn); \
        guest_memory_shutdown(); \
        return 1; \
    } \
} while (0)

#define TEST_PROT_NONE  ((enum GuestMemoryProtection)0)
#define TEST_PROT_READ  ((enum GuestMemoryProtection)1)
#define TEST_PROT_WRITE ((enum GuestMemoryProtection)2)

static const GuestImport IMP_GET_LAST_ERROR = {
    .iat = 0x00401000U,
    .library = "kernel32.dll",
    .name = "GetLastError"
};

static const GuestImport IMP_SET_LAST_ERROR = {
    .iat = 0x00401004U,
    .library = "kernel32.dll",
    .name = "SetLastError"
};

static void write_u32(uint32_t addr, uint32_t val) {
    void *p = guest_memory_pointer(addr, sizeof(val), 1);
    if (!p) {
        fprintf(stderr, "write_u32 failed at 0x%" PRIx32 "\n", addr);
        abort();
    }
    memcpy(p, &val, sizeof(val));
}

static uint32_t read_u32(uint32_t addr) {
    void *p = guest_memory_pointer(addr, sizeof(uint32_t), 0);
    if (!p) {
        fprintf(stderr, "read_u32 failed at 0x%" PRIx32 "\n", addr);
        abort();
    }
    uint32_t val = 0;
    memcpy(&val, p, sizeof(val));
    return val;
}

static int cpu_identical(const CPU *a, const CPU *b) {
    if (a->eax != b->eax) return 0;
    if (a->ecx != b->ecx) return 0;
    if (a->edx != b->edx) return 0;
    if (a->ebx != b->ebx) return 0;
    if (a->esp != b->esp) return 0;
    if (a->ebp != b->ebp) return 0;
    if (a->esi != b->esi) return 0;
    if (a->edi != b->edi) return 0;
    if (a->eip != b->eip) return 0;
    if (a->fs_base != b->fs_base) return 0;
    if (a->gs_base != b->gs_base) return 0;
    if (eflags_get((CPU *)a) != eflags_get((CPU *)b)) return 0;
    return memcmp(a, b, sizeof(CPU)) == 0;
}

static void init_test_cpu(CPU *cpu, uint32_t fs_base, uint32_t esp) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0xAAAAAAAAU;
    cpu->ecx = 0x11111111U;
    cpu->edx = 0x22222222U;
    cpu->ebx = 0x33333333U;
    cpu->esp = esp;
    cpu->ebp = 0x44444444U;
    cpu->esi = 0x55555555U;
    cpu->edi = 0x66666666U;
    cpu->eip = 0x00400000U;
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x77770000U;
    eflags_set(cpu, 0x00000246U);
}

static void setup_stack_argc0(uint32_t esp, uint32_t ret_ip) {
    write_u32(esp, ret_ip);
}

static void setup_stack_argc1(uint32_t esp, uint32_t ret_ip, uint32_t arg0) {
    write_u32(esp, ret_ip);
    write_u32(esp + 4U, arg0);
}

static int setup_test_environment(void) {
    REQUIRE_VM(guest_memory_commit(0x10000U, 0x4000ULL));
    REQUIRE_VM(guest_memory_protect(0x10000U, 0x4000ULL, TEST_PROT_WRITE));
    if (!guest_memory_pointer(0x10000U, 0x4000ULL, 1)) return 0;

    REQUIRE_VM(guest_memory_commit(0x20000U, 0x4000ULL));
    REQUIRE_VM(guest_memory_protect(0x20000U, 0x4000ULL, TEST_PROT_WRITE));
    if (!guest_memory_pointer(0x20000U, 0x4000ULL, 1)) return 0;

    REQUIRE_VM(guest_memory_commit(0x30000U, 0x4000ULL));
    REQUIRE_VM(guest_memory_protect(0x30000U, 0x4000ULL, TEST_PROT_WRITE));
    if (!guest_memory_pointer(0x30000U, 0x4000ULL, 1)) return 0;

    REQUIRE_VM(guest_memory_commit(0x40000U, 0x4000ULL));
    REQUIRE_VM(guest_memory_protect(0x40000U, 0x4000ULL, TEST_PROT_WRITE));
    if (!guest_memory_pointer(0x40000U, 0x4000ULL, 1)) return 0;

    return 1;
}

static int test_unknown_and_malformed_inputs(void) {
    CPU cpu;
    init_test_cpu(&cpu, 0x20000U, 0x12000U);
    CPU snap = cpu;
    uint32_t fault = 0xBAADF00DU;

    CHECK(guest_error_import(NULL, &IMP_GET_LAST_ERROR, &fault) == 0);
    CHECK(guest_error_import(&cpu, NULL, &fault) == 0);
    CHECK(guest_error_import(&cpu, &IMP_GET_LAST_ERROR, NULL) == 0);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(fault == 0xBAADF00DU);

    GuestImport bad_lib = { 0x00401000U, NULL, "GetLastError" };
    CHECK(guest_error_import(&cpu, &bad_lib, &fault) == 0);
    GuestImport bad_name = { 0x00401000U, "kernel32.dll", NULL };
    CHECK(guest_error_import(&cpu, &bad_name, &fault) == 0);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(fault == 0xBAADF00DU);

    GuestImport user32 = { 0x00401000U, "user32.dll", "GetLastError" };
    CHECK(guest_error_import(&cpu, &user32, &fault) == 0);
    GuestImport ntdll = { 0x00401000U, "ntdll.dll", "GetLastError" };
    CHECK(guest_error_import(&cpu, &ntdll, &fault) == 0);
    GuestImport empty_lib = { 0x00401000U, "", "GetLastError" };
    CHECK(guest_error_import(&cpu, &empty_lib, &fault) == 0);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(fault == 0xBAADF00DU);

    GuestImport other_api = { 0x00401000U, "kernel32.dll", "CreateFileA" };
    CHECK(guest_error_import(&cpu, &other_api, &fault) == 0);
    GuestImport set_ex = { 0x00401000U, "kernel32.dll", "SetLastErrorEx" };
    CHECK(guest_error_import(&cpu, &set_ex, &fault) == 0);
    GuestImport lower_get = { 0x00401000U, "kernel32.dll", "getlasterror" };
    CHECK(guest_error_import(&cpu, &lower_get, &fault) == 0);
    GuestImport upper_set = { 0x00401000U, "kernel32.dll", "SETLASTERROR" };
    CHECK(guest_error_import(&cpu, &upper_set, &fault) == 0);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(fault == 0xBAADF00DU);

    return 0;
}

static int test_dll_case_insensitivity(void) {
    const char *dll_names[] = {
        "kernel32.dll",
        "KERNEL32.DLL",
        "Kernel32.dll",
        "kErNeL32.DlL",
        "KERNEL32.dll"
    };
    size_t count = sizeof(dll_names) / sizeof(dll_names[0]);

    for (size_t i = 0; i < count; ++i) {
        CPU cpu;
        uint32_t fault = 0x12345678U;
        GuestImport imp_set = { 0, dll_names[i], "SetLastError" };
        GuestImport imp_get = { 0, dll_names[i], "GetLastError" };

        init_test_cpu(&cpu, 0x20000U, 0x12000U);
        setup_stack_argc1(0x12000U, 0x00402000U, 0x100U + (uint32_t)i);
        CHECK(guest_error_import(&cpu, &imp_set, &fault) == 1);
        CHECK(cpu.eip == 0x00402000U);
        CHECK(cpu.esp == 0x12008U);
        CHECK(read_u32(0x20034U) == 0x100U + (uint32_t)i);

        init_test_cpu(&cpu, 0x20000U, 0x12000U);
        setup_stack_argc0(0x12000U, 0x00403000U);
        CHECK(guest_error_import(&cpu, &imp_get, &fault) == 1);
        CHECK(cpu.eip == 0x00403000U);
        CHECK(cpu.esp == 0x12004U);
        CHECK(cpu.eax == 0x100U + (uint32_t)i);
    }

    return 0;
}

static int test_set_and_get_raw_values(void) {
    const uint32_t test_values[] = {
        0x00000000U,
        0xFFFFFFFFU,
        0x12345678U,
        0x80070005U,
        0xCAFEBABEU,
        0x00000005U,
        0xDEADBEEFU
    };
    size_t count = sizeof(test_values) / sizeof(test_values[0]);

    for (size_t i = 0; i < count; ++i) {
        uint32_t val = test_values[i];
        CPU cpu;
        uint32_t fault = 0;

        init_test_cpu(&cpu, 0x20000U, 0x12000U);
        setup_stack_argc1(0x12000U, 0x00402000U, val);
        uint32_t eax_before = cpu.eax;
        CHECK(guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault) == 1);
        CHECK(read_u32(0x20034U) == val);
        CHECK(cpu.eax == eax_before);
        CHECK(cpu.esp == 0x12008U);
        CHECK(cpu.eip == 0x00402000U);
        CHECK(eflags_get(&cpu) == 0x00000246U);

        init_test_cpu(&cpu, 0x20000U, 0x12000U);
        setup_stack_argc0(0x12000U, 0x00403000U);
        CHECK(guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault) == 1);
        CHECK(cpu.eax == val);
        CHECK(cpu.esp == 0x12004U);
        CHECK(cpu.eip == 0x00403000U);
        CHECK(eflags_get(&cpu) == 0x00000246U);
    }

    return 0;
}

static int test_stdcall_preservation(void) {
    CPU cpu;
    uint32_t fault = 0;

    write_u32(0x20034U, 0x55AA55AAU);

    init_test_cpu(&cpu, 0x20000U, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00405000U);
    CHECK(guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault) == 1);
    CHECK(cpu.eax == 0x55AA55AAU);
    CHECK(cpu.eip == 0x00405000U);
    CHECK(cpu.esp == 0x12004U);
    CHECK(cpu.ecx == 0x11111111U);
    CHECK(cpu.edx == 0x22222222U);
    CHECK(cpu.ebx == 0x33333333U);
    CHECK(cpu.ebp == 0x44444444U);
    CHECK(cpu.esi == 0x55555555U);
    CHECK(cpu.edi == 0x66666666U);
    CHECK(cpu.fs_base == 0x20000U);
    CHECK(cpu.gs_base == 0x77770000U);
    CHECK(eflags_get(&cpu) == 0x00000246U);
    CHECK(read_u32(0x12000U) == 0x00405000U);

    init_test_cpu(&cpu, 0x20000U, 0x12000U);
    setup_stack_argc1(0x12000U, 0x00406000U, 0x12344321U);
    CHECK(guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault) == 1);
    CHECK(cpu.eax == 0xAAAAAAAAU);
    CHECK(cpu.eip == 0x00406000U);
    CHECK(cpu.esp == 0x12008U);
    CHECK(cpu.ecx == 0x11111111U);
    CHECK(cpu.edx == 0x22222222U);
    CHECK(cpu.ebx == 0x33333333U);
    CHECK(cpu.ebp == 0x44444444U);
    CHECK(cpu.esi == 0x55555555U);
    CHECK(cpu.edi == 0x66666666U);
    CHECK(cpu.fs_base == 0x20000U);
    CHECK(cpu.gs_base == 0x77770000U);
    CHECK(eflags_get(&cpu) == 0x00000246U);
    CHECK(read_u32(0x20034U) == 0x12344321U);
    CHECK(read_u32(0x12000U) == 0x00406000U);
    CHECK(read_u32(0x12004U) == 0x12344321U);

    return 0;
}

static int test_teb_isolation(void) {
    CPU cpu1, cpu2;
    uint32_t fault = 0;

    init_test_cpu(&cpu1, 0x20000U, 0x12000U);
    setup_stack_argc1(0x12000U, 0x00401000U, 0x11111111U);
    CHECK(guest_error_import(&cpu1, &IMP_SET_LAST_ERROR, &fault) == 1);

    init_test_cpu(&cpu2, 0x30000U, 0x12010U);
    setup_stack_argc1(0x12010U, 0x00402000U, 0x22222222U);
    CHECK(guest_error_import(&cpu2, &IMP_SET_LAST_ERROR, &fault) == 1);

    CHECK(read_u32(0x20034U) == 0x11111111U);
    CHECK(read_u32(0x30034U) == 0x22222222U);

    init_test_cpu(&cpu1, 0x20000U, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00401000U);
    CHECK(guest_error_import(&cpu1, &IMP_GET_LAST_ERROR, &fault) == 1);
    CHECK(cpu1.eax == 0x11111111U);

    init_test_cpu(&cpu2, 0x30000U, 0x12010U);
    setup_stack_argc0(0x12010U, 0x00402000U);
    CHECK(guest_error_import(&cpu2, &IMP_GET_LAST_ERROR, &fault) == 1);
    CHECK(cpu2.eax == 0x22222222U);

    init_test_cpu(&cpu1, 0x20000U, 0x12000U);
    setup_stack_argc1(0x12000U, 0x00401000U, 0x33333333U);
    CHECK(guest_error_import(&cpu1, &IMP_SET_LAST_ERROR, &fault) == 1);
    CHECK(read_u32(0x20034U) == 0x33333333U);
    CHECK(read_u32(0x30034U) == 0x22222222U);

    init_test_cpu(&cpu2, 0x30000U, 0x12010U);
    setup_stack_argc0(0x12010U, 0x00402000U);
    CHECK(guest_error_import(&cpu2, &IMP_GET_LAST_ERROR, &fault) == 1);
    CHECK(cpu2.eax == 0x22222222U);

    return 0;
}

static int test_read_only_teb(void) {
    REQUIRE_VM(guest_memory_protect(0x40000U, 0x4000ULL, TEST_PROT_WRITE));
    write_u32(0x40034U, 0x99887766U);
    REQUIRE_VM(guest_memory_protect(0x40000U, 0x4000ULL, TEST_PROT_READ));
    CPU cpu;
    uint32_t fault = 0;

    init_test_cpu(&cpu, 0x40000U, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00407000U);
    CHECK(guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault) == 1);
    CHECK(cpu.eax == 0x99887766U);
    CHECK(cpu.eip == 0x00407000U);
    CHECK(cpu.esp == 0x12004U);

    init_test_cpu(&cpu, 0x40000U, 0x12000U);
    setup_stack_argc1(0x12000U, 0x00408000U, 0x11223344U);
    CPU snap = cpu;
    fault = 0;
    int rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0x40034U);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(read_u32(0x40034U) == 0x99887766U);
    CHECK(read_u32(0x12000U) == 0x00408000U);
    CHECK(read_u32(0x12004U) == 0x11223344U);

    REQUIRE_VM(guest_memory_protect(0x40000U, 0x4000ULL, TEST_PROT_WRITE));
    return 0;
}

static int test_zero_teb(void) {
    CPU cpu;
    uint32_t fault = 0x55555555U;

    init_test_cpu(&cpu, 0x00000000U, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00401000U);
    CPU snap = cpu;

    int rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0U);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(read_u32(0x12000U) == 0x00401000U);

    setup_stack_argc1(0x12000U, 0x00402000U, 0xCAFEU);
    snap = cpu;
    fault = 0x55555555U;

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -2);
    CHECK(fault == 0U);
    CHECK(cpu_identical(&cpu, &snap));
    CHECK(read_u32(0x12000U) == 0x00402000U);
    CHECK(read_u32(0x12004U) == 0xCAFEU);

    return 0;
}

static int test_overflow_teb(void) {
    CPU cpu;
    uint32_t fault = 0;

    init_test_cpu(&cpu, 0xFFFFFFE0U, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00401000U);
    CPU snap = cpu;

    int rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == UINT32_MAX);
    CHECK(cpu_identical(&cpu, &snap));

    setup_stack_argc1(0x12000U, 0x00402000U, 0x1234U);
    snap = cpu;
    fault = 0;

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == UINT32_MAX);
    CHECK(cpu_identical(&cpu, &snap));

    init_test_cpu(&cpu, 0xFFFFFFFFU, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00401000U);
    snap = cpu;
    fault = 0;

    rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == UINT32_MAX);
    CHECK(cpu_identical(&cpu, &snap));

    return 0;
}

static int test_unmapped_teb(void) {
    CPU cpu;
    uint32_t fault = 0;
    uint32_t unmapped_fs = 0x00500000U;
    uint32_t expected_teb_addr = unmapped_fs + 0x34U;

    init_test_cpu(&cpu, unmapped_fs, 0x12000U);
    setup_stack_argc0(0x12000U, 0x00401000U);
    CPU snap = cpu;

    int rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == expected_teb_addr);
    CHECK(cpu_identical(&cpu, &snap));

    setup_stack_argc1(0x12000U, 0x00402000U, 0x9999U);
    snap = cpu;
    fault = 0;

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(fault == expected_teb_addr);
    CHECK(cpu_identical(&cpu, &snap));

    return 0;
}

static int test_bad_and_wrapped_frames(void) {
    CPU cpu;
    uint32_t fault = 0x77777777U;

    init_test_cpu(&cpu, 0x20000U, 0x00600000U);
    CPU snap = cpu;

    int rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    init_test_cpu(&cpu, 0x20000U, 0xFFFFFFFDU);
    snap = cpu;

    rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    init_test_cpu(&cpu, 0x20000U, 0xFFFFFFFCU);
    snap = cpu;

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    init_test_cpu(&cpu, 0x20000U, 0xFFFFFFFFU);
    snap = cpu;

    rc = guest_error_import(&cpu, &IMP_GET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    rc = guest_error_import(&cpu, &IMP_SET_LAST_ERROR, &fault);
    CHECK(rc == -1);
    CHECK(cpu_identical(&cpu, &snap));

    return 0;
}

int main(void) {
    if (guest_memory_init() != 0) {
        fprintf(stderr, "guest_memory guest_memory_init() failed\n");
        return 1;
    }

    if (!setup_test_environment()) {
        fprintf(stderr, "setup_test_environment failed\n");
        guest_memory_shutdown();
        return 1;
    }

    RUN_TEST(test_unknown_and_malformed_inputs);
    RUN_TEST(test_dll_case_insensitivity);
    RUN_TEST(test_set_and_get_raw_values);
    RUN_TEST(test_stdcall_preservation);
    RUN_TEST(test_teb_isolation);
    RUN_TEST(test_read_only_teb);
    RUN_TEST(test_zero_teb);
    RUN_TEST(test_overflow_teb);
    RUN_TEST(test_unmapped_teb);
    RUN_TEST(test_bad_and_wrapped_frames);

    if (guest_memory_shutdown() != 0) {
        fprintf(stderr, "guest_memory guest_memory_shutdown() failed\n");
        return 1;
    }

    printf("PASS | guest LastError contracts\n");
    return 0;
}
