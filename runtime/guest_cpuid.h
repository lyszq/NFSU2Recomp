/*
 * Static CPUID profile for the portable 32-bit guest runtime.
 *
 * This describes the upstream translated guest's existing x86 profile; it
 * does not claim to report the physical host processor.
 */
#ifndef NFSU2_GUEST_CPUID_H
#define NFSU2_GUEST_CPUID_H

#include "cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Profile: upstream_static_x86_006d8.
 * Handles basic leaves 0 and 1, plus the extended-leaf maximum query
 * 0x80000000 (which returns four zero registers, matching the legacy profile).
 * Returns 1 when handled,
 * 0 when the CPU pointer or requested leaf is unsupported. Unsupported
 * leaves leave the entire CPU state unchanged.
 */
int guest_cpuid(CPU *cpu);

#ifdef __cplusplus
}
#endif

#endif /* NFSU2_GUEST_CPUID_H */
