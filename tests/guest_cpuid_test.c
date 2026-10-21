#include "guest_cpuid.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static void init_cpu(CPU *cpu, uint32_t leaf) {
    memset(cpu, 0x69, sizeof(*cpu));
    cpu->eax = leaf;
    cpu->ecx = 0x13579bdfu; /* Subleaf/input must be overwritten for known leaves. */
    cpu->edx = 0x2468ace0u;
    cpu->ebx = 0xdeadbeefu;
    cpu->esp = 0x00102030u;
    cpu->eip = 0x00405678u;
    cpu->fs_base = 0x00c00000u;
    cpu->gs_base = 0x00d00000u;
    cpu->cf = 1u;
    cpu->pf = 0u;
    cpu->af = 1u;
    cpu->zf = 1u;
    cpu->sf = 0u;
    cpu->of = 1u;
    cpu->df = 1u;
    cpu->st[0] = 3.25;
    cpu->st[7] = -19.5;
    cpu->top = 6;
    cpu->fcw = 0x027fu;
    cpu->fsw = 0x4321u;
    cpu->mm[3] = UINT64_C(0x0123456789abcdef);
    cpu->xmm[4].u64[0] = UINT64_C(0xfedcba9876543210);
    cpu->xmm[4].u64[1] = UINT64_C(0x1122334455667788);
}

static int check_leaf(uint32_t leaf, uint32_t eax, uint32_t ebx,
                      uint32_t ecx, uint32_t edx) {
    CPU cpu, expected;
    init_cpu(&cpu, leaf);
    memcpy(&expected, &cpu, sizeof(cpu));
    expected.eax = eax;
    expected.ebx = ebx;
    expected.ecx = ecx;
    expected.edx = edx;

    CHECK(guest_cpuid(&cpu) == 1);
    if (memcmp(&cpu, &expected, sizeof(cpu)) != 0) {
        fprintf(stderr,
                "FAIL %s:%d: leaf %08x changed wrong CPU fields "
                "(eax=%08x ebx=%08x ecx=%08x edx=%08x)\n",
                __FILE__, __LINE__, leaf, cpu.eax, cpu.ebx, cpu.ecx, cpu.edx);
        return 1;
    }
    return 0;
}

static int test_known_leaves(void) {
    /* EBX:EDX:ECX bytes spell GenuineIntel in the specified vendor order. */
    CHECK(check_leaf(0u, 1u, 0x756e6547u, 0x6c65746eu, 0x49656e69u) == 0);
    CHECK(check_leaf(1u, 0x000006d8u, 0u, 0u, 0x0383fbffu) == 0);
    CHECK(check_leaf(0x80000000u, 0u, 0u, 0u, 0u) == 0);
    return 0;
}

static int test_unknown_leaves_and_null(void) {
    static const uint32_t unknown[] = {
        2u, 0x80000001u, 0xffffffffu
    };
    CPU cpu, before;

    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i) {
        init_cpu(&cpu, unknown[i]);
        memcpy(&before, &cpu, sizeof(cpu));
        CHECK(guest_cpuid(&cpu) == 0);
        CHECK(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    }

    CHECK(guest_cpuid(NULL) == 0);
    return 0;
}

int main(void) {
    CHECK(test_known_leaves() == 0);
    CHECK(test_unknown_leaves_and_null() == 0);
    puts("PASS guest_cpuid_test");
    return 0;
}
