#include "guest_cpuid.h"

int guest_cpuid(CPU *cpu) {
    if (!cpu) return 0;

    switch (cpu->eax) {
    case 0:
        /* "GenuineIntel" is the upstream guest profile vendor string. */
        cpu->eax = 1u;
        cpu->ebx = 0x756e6547u; /* Genu */
        cpu->edx = 0x49656e69u; /* ineI */
        cpu->ecx = 0x6c65746eu; /* ntel */
        return 1;

    case 1:
        cpu->eax = 0x000006d8u;
        cpu->ebx = 0u;
        cpu->ecx = 0u; /* No modern ECX feature bits are advertised. */
        cpu->edx = 0x0383fbffu;
        return 1;

    case 0x80000000u:
    case 0x80000001u:
        /* Match the legacy guest profile's all-zero extended-leaf responses;
         * leaf 0x80000001 advertises no AMD extended features. */
        cpu->eax = 0u;
        cpu->ebx = 0u;
        cpu->ecx = 0u;
        cpu->edx = 0u;
        return 1;

    default:
        return 0;
    }
}
