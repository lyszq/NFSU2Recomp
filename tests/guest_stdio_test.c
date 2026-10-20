#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "cpu.h"
#include "guest_memory.h"
#include "guest_stdio.h"

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

static int write_u32(uint32_t addr, uint32_t val) {
    void *p = guest_memory_pointer(addr, sizeof(val), 1);
    CHECK(p != NULL);
    memcpy(p, &val, sizeof(val));
    return 0;
}

static uint32_t read_u32(uint32_t addr) {
    void *p = guest_memory_pointer(addr, sizeof(uint32_t), 0);
    if (!p) return 0xFFFFFFFFu;
    uint32_t val = 0;
    memcpy(&val, p, sizeof(val));
    return val;
}

static void init_cpu(CPU *cpu, uint32_t esp, uint32_t fs) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = esp;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = 0x88888888u;
    cpu->fs_base = fs;
    cpu->gs_base = 0x99999999u;
    eflags_set(cpu, 0x246u);
}

static int cpu_identical(const CPU *a, const CPU *b) {
    CHECK(a->eax == b->eax && a->ecx == b->ecx && a->edx == b->edx);
    CHECK(a->ebx == b->ebx && a->esp == b->esp && a->ebp == b->ebp);
    CHECK(a->esi == b->esi && a->edi == b->edi && a->eip == b->eip);
    CHECK(a->fs_base == b->fs_base && a->gs_base == b->gs_base);
    CHECK(eflags_get((CPU *)a) == eflags_get((CPU *)b));
    return 0;
}

static int cpu_success(const CPU *cur, const CPU *orig, uint32_t ret_eip, uint32_t exp_esp) {
    CHECK(cur->eax == 0);
    CHECK(cur->ecx == orig->ecx && cur->edx == orig->edx && cur->ebx == orig->ebx);
    CHECK(cur->esp == exp_esp && cur->ebp == orig->ebp);
    CHECK(cur->esi == orig->esi && cur->edi == orig->edi && cur->eip == ret_eip);
    CHECK(cur->fs_base == orig->fs_base && cur->gs_base == orig->gs_base);
    CHECK(eflags_get((CPU *)cur) == eflags_get((CPU *)orig));
    return 0;
}

static int test_get_std_handle_success(void) {
    const uint32_t selectors[3] = {0xFFFFFFF6u, 0xFFFFFFF5u, 0xFFFFFFF4u};
    const GuestImport imp = {0, "KERNEL32.dll", "GetStdHandle"};

    for (int i = 0; i < 3; i++) {
        uint32_t esp = STACK_ADDR + 0x100u + (uint32_t)(i * 0x20);
        CHECK(write_u32(esp, RET_ADDR + (uint32_t)i) == 0);
        CHECK(write_u32(esp + 4, selectors[i]) == 0);
        CHECK(write_u32(TEB_ADDR + 0x34, 0x12345670u + (uint32_t)i) == 0);

        uint32_t fs_bases[3] = {TEB_ADDR, 0u, 0xDEAD0000u};
        for (int j = 0; j < 3; j++) {
            CPU cpu, orig;
            init_cpu(&cpu, esp, fs_bases[j]);
            orig = cpu;
            uint32_t fault = SENTINEL;

            int rc = guest_stdio_import(&cpu, &imp, &fault);
            CHECK(rc == 1);
            CHECK(fault == SENTINEL);
            CHECK(cpu_success(&cpu, &orig, RET_ADDR + (uint32_t)i, esp + 8) == 0);
            CHECK(read_u32(TEB_ADDR + 0x34) == 0x12345670u + (uint32_t)i);
            CHECK(read_u32(esp) == RET_ADDR + (uint32_t)i);
            CHECK(read_u32(esp + 4) == selectors[i]);
        }
    }
    return 0;
}

static int test_unsupported_and_variants(void) {
    uint32_t esp = STACK_ADDR + 0x200u;
    CHECK(write_u32(esp, RET_ADDR) == 0);
    CHECK(write_u32(TEB_ADDR + 0x34, 0xAABBCCDDu) == 0);

    const GuestImport imp_valid = {0, "KERNEL32.dll", "GetStdHandle"};
    const uint32_t bad_selectors[5] = {0xFFFFFFF7u, 0xFFFFFFF3u, 0u, 1u, 0xFFFFFFFFu};

    for (int i = 0; i < 5; i++) {
        CHECK(write_u32(esp + 4, bad_selectors[i]) == 0);
        CPU cpu, orig;
        init_cpu(&cpu, esp, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_valid, &fault);
        CHECK(rc == 0);
        CHECK(fault == SENTINEL);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(TEB_ADDR + 0x34) == 0xAABBCCDDu);
    }

    const GuestImport imp_null_lib  = {0, NULL, "GetStdHandle"};
    const GuestImport imp_alias     = {0, "kernel32", "GetStdHandle"};
    const GuestImport imp_other_dll = {0, "USER32.dll", "GetStdHandle"};
    const GuestImport imp_null_name = {0, "KERNEL32.dll", NULL};
    const GuestImport imp_bad_name  = {0, "KERNEL32.dll", "GetStdHandleEx"};
    const GuestImport imp_other_api = {0, "KERNEL32.dll", "CreateFileA"};

    const GuestImport *bad_imps[6] = {
        &imp_null_lib, &imp_alias, &imp_other_dll,
        &imp_null_name, &imp_bad_name, &imp_other_api
    };

    CHECK(write_u32(esp + 4, 0xFFFFFFF6u) == 0);

    for (size_t i = 0; i < sizeof(bad_imps)/sizeof(bad_imps[0]); i++) {
        CPU cpu, orig;
        init_cpu(&cpu, esp, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, bad_imps[i], &fault);
        CHECK(rc == 0);
        CHECK(fault == SENTINEL);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(TEB_ADDR + 0x34) == 0xAABBCCDDu);
    }

    CPU cpu, orig;
    init_cpu(&cpu, esp, TEB_ADDR);
    orig = cpu;
    uint32_t fault = SENTINEL;

    CHECK(guest_stdio_import(&cpu, NULL, &fault) == 0);
    CHECK(fault == SENTINEL);
    CHECK(cpu_identical(&cpu, &orig) == 0);

    CHECK(guest_stdio_import(NULL, &imp_valid, &fault) == 0);
    CHECK(fault == SENTINEL);

    CHECK(guest_stdio_import(&cpu, &imp_valid, NULL) == 0);
    CHECK(cpu_identical(&cpu, &orig) == 0);

    const GuestImport imp_lower = {0, "kernel32.dll", "GetStdHandle"};
    const GuestImport imp_mixed = {0, "Kernel32.DLL", "GetStdHandle"};

    init_cpu(&cpu, esp, TEB_ADDR);
    orig = cpu;
    CHECK(guest_stdio_import(&cpu, &imp_lower, &fault) == 1);
    CHECK(cpu_success(&cpu, &orig, RET_ADDR, esp + 8) == 0);

    init_cpu(&cpu, esp, TEB_ADDR);
    orig = cpu;
    CHECK(guest_stdio_import(&cpu, &imp_mixed, &fault) == 1);
    CHECK(cpu_success(&cpu, &orig, RET_ADDR, esp + 8) == 0);

    return 0;
}

static int test_get_file_type(void) {
    uint32_t esp = STACK_ADDR + 0x300u;
    const GuestImport imp_ft = {0, "KERNEL32.dll", "GetFileType"};
    const uint32_t valid_handles[2] = {0u, 0xFFFFFFFFu};

    for (int i = 0; i < 2; i++) {
        CHECK(write_u32(esp, RET_ADDR) == 0);
        CHECK(write_u32(esp + 4, valid_handles[i]) == 0);
        CHECK(write_u32(TEB_ADDR + 0x34, 0x1111u) == 0);

        CPU cpu, orig;
        init_cpu(&cpu, esp, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == 1);
        CHECK(fault == SENTINEL);
        CHECK(cpu_success(&cpu, &orig, RET_ADDR, esp + 8) == 0);
        CHECK(read_u32(TEB_ADDR + 0x34) == 6u);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == valid_handles[i]);
    }

    const uint32_t unsupported_handles[4] = {1u, 2u, 42u, 0x1000u};
    for (int i = 0; i < 4; i++) {
        CHECK(write_u32(esp, RET_ADDR) == 0);
        CHECK(write_u32(esp + 4, unsupported_handles[i]) == 0);
        CHECK(write_u32(TEB_ADDR + 0x34, 0x5555AAAAu) == 0);

        CPU cpu, orig;
        init_cpu(&cpu, esp, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == 0);
        CHECK(fault == SENTINEL);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(TEB_ADDR + 0x34) == 0x5555AAAAu);
    }

    return 0;
}

static int test_stack_faults_and_zero_teb(void) {
    const GuestImport imp_sh = {0, "KERNEL32.dll", "GetStdHandle"};
    const GuestImport imp_ft = {0, "KERNEL32.dll", "GetFileType"};

    {
        CPU cpu, orig;
        init_cpu(&cpu, 0x80000u, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_sh, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x80000u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
    }

    {
        CPU cpu, orig;
        init_cpu(&cpu, 0xFFFFFFFCu, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFCu);
        CHECK(cpu_identical(&cpu, &orig) == 0);
    }

    {
        uint32_t unmapped_page = 0x40000u;
        CHECK(guest_memory_commit(unmapped_page, GUEST_MEMORY_GRANULE) == 0);
        CHECK(guest_memory_protect(unmapped_page, GUEST_MEMORY_GRANULE, GUEST_MEMORY_NONE) == 0);

        CPU cpu, orig;
        init_cpu(&cpu, unmapped_page + 0x10u, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_sh, &fault);
        CHECK(rc == -1);
        CHECK(fault == unmapped_page + 0x10u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
    }

    {
        uint32_t esp = STACK_ADDR + 0x400u;
        CHECK(write_u32(esp, RET_ADDR) == 0);
        CHECK(write_u32(esp + 4, 0u) == 0);

        CPU cpu, orig;
        init_cpu(&cpu, esp, 0u);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -2);
        CHECK(fault == 0u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == 0u);
    }

    return 0;
}

static int test_teb_faults_and_atomicity(void) {
    const GuestImport imp_ft = {0, "KERNEL32.dll", "GetFileType"};
    uint32_t esp = STACK_ADDR + 0x500u;
    CHECK(write_u32(esp, RET_ADDR) == 0);
    CHECK(write_u32(esp + 4, 0u) == 0);

    {
        CPU cpu, orig;
        init_cpu(&cpu, esp, 0x90000u);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x90034u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == 0u);
    }

    {
        uint32_t ro_page = 0x50000u;
        CHECK(guest_memory_commit(ro_page, GUEST_MEMORY_GRANULE) == 0);
        CHECK(guest_memory_protect(ro_page, GUEST_MEMORY_GRANULE, GUEST_MEMORY_READ) == 0);

        CPU cpu, orig;
        init_cpu(&cpu, esp, ro_page);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == ro_page + 0x34u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == 0u);
    }

    {
        CPU cpu, orig;
        init_cpu(&cpu, esp, 0xFFFFFFE0u);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFFu);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == 0u);
    }

    {
        CPU cpu, orig;
        init_cpu(&cpu, esp, 0xFFFFFFCBu);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0xFFFFFFFFu);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(esp) == RET_ADDR);
        CHECK(read_u32(esp + 4) == 0u);
    }

    {
        CHECK(write_u32(TEB_ADDR + 0x34, 0xBEEFCAFEu) == 0);
        CPU cpu, orig;
        init_cpu(&cpu, 0x85000u, TEB_ADDR);
        orig = cpu;
        uint32_t fault = SENTINEL;

        int rc = guest_stdio_import(&cpu, &imp_ft, &fault);
        CHECK(rc == -1);
        CHECK(fault == 0x85000u);
        CHECK(cpu_identical(&cpu, &orig) == 0);
        CHECK(read_u32(TEB_ADDR + 0x34) == 0xBEEFCAFEu);
    }

    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_ADDR, GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(TEB_ADDR, GUEST_MEMORY_GRANULE) == 0);

    CHECK(test_get_std_handle_success() == 0);
    CHECK(test_unsupported_and_variants() == 0);
    CHECK(test_get_file_type() == 0);
    CHECK(test_stack_faults_and_zero_teb() == 0);
    CHECK(test_teb_faults_and_atomicity() == 0);

    CHECK(guest_memory_shutdown() == 0);
    printf("PASS\n");
    return 0;
}
