/*
 * NFSU2 iOS stage 2: REAL upstream guest CPU structure + x86 flag helpers,
 * paired with a self-contained, iOS-safe 32-bit guest virtual-memory smoke test.
 *
 * Upstream macOS cpu.h is included directly rather than defining a pretend CPU.
 * We do NOT link or execute any generated proprietary game code here.
 * The macOS mem.c is deliberately not linked: it installs debug signal handlers
 * and has desktop-only facilities.  Once this probe passes on-device, its
 * allocations can be connected to a refactored, shared guest memory module.
 */
#include "GuestSmoke.h"
#include "../../../runtime/cpu.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int fail(char *out, size_t n, const char *phase, int err) {
    if (n) {
        if (err) {
            (void)snprintf(out, n, "FAIL | %s | errno=%d (%s)", phase, err, strerror(err));
        } else {
            (void)snprintf(out, n, "FAIL | %s", phase);
        }
    }
    return 1;
}

static int test_x86_cpu(char *out, size_t n) {
    CPU context = {0};
    CPU *c = &context;

    /* The exact registers/flag macros from upstream runtime/cpu.h. */
    c->eax = 0x7fffffffu;
    c->ebx = 1u;
    uint32_t a = c->eax, b = c->ebx;
    uint32_t r = a + b;
    FLAGS_ADD_M(a, b, r, 32, F_ALL);
    c->eax = r;
    if (c->eax != 0x80000000u || c->of != 1u || c->sf != 1u ||
        c->cf != 0u || c->zf != 0u) {
        return fail(out, n, "x86 signed-overflow / EFLAGS", 0);
    }

    c->eax = 0xffffffffu;
    a = c->eax;
    r = a + b;
    FLAGS_ADD_M(a, b, r, 32, F_ALL);
    c->eax = r;
    if (c->eax != 0u || c->cf != 1u || c->zf != 1u ||
        c->sf != 0u || c->of != 0u || c->pf != 1u) {
        return fail(out, n, "x86 carry/zero/parity flags", 0);
    }

    a = 0u; b = 1u; r = a - b;
    FLAGS_SUB_M(a, b, r, 32, F_ALL);
    if (r != 0xffffffffu || c->cf != 1u || c->sf != 1u ||
        c->of != 0u || c->zf != 0u) {
        return fail(out, n, "x86 subtraction / borrow", 0);
    }

    /* Structural x87/MMX/XMM register storage probe (not an instruction test). */
    c->st[0] = 1.5;
    c->mm[0] = UINT64_C(0x1234567887654321);
    c->xmm[0].u32[0] = 0xdeadbeefu;
    if (c->st[0] != 1.5 || c->mm[0] != UINT64_C(0x1234567887654321) ||
        c->xmm[0].u32[0] != 0xdeadbeefu) {
        return fail(out, n, "x87/MMX/XMM register storage", 0);
    }
    return 0;
}

static int test_guest_address_space(char *out, size_t n, long *page_size) {
    const long ps = sysconf(_SC_PAGESIZE);
    if (ps < 4096 || ((unsigned long)ps & ((unsigned long)ps - 1u)) != 0u) {
        return fail(out, n, "invalid host VM page size", 0);
    }
    *page_size = ps;

    /* Reserve, do not allocate, the 4 GiB x86-32 virtual guest address space.
     * PROT_NONE means no physical pages are committed by this operation.
     * Important: iOS may reject this; failure is surfaced, never hidden.
     */
    uint8_t *const region = mmap(NULL, (size_t)GSZ, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region == MAP_FAILED) {
        return fail(out, n, "reserve 4 GiB guest virtual address space", errno);
    }

    const uint32_t guest_addresses[] = {
        UINT32_C(0x00400040),  /* PE image */
        UINT32_C(0x10000040),  /* guest heap */
        UINT32_C(0xF0000040)   /* high 32-bit guest address */
    };
    int result = 0;
    for (unsigned i = 0; i < sizeof guest_addresses / sizeof guest_addresses[0]; i++) {
        uint32_t addr = guest_addresses[i];
        size_t page_base = (size_t)addr & ~((size_t)ps - 1u);
        if (mprotect(region + page_base, (size_t)ps, PROT_READ | PROT_WRITE) != 0) {
            result = fail(out, n, "commit guest VM page", errno);
            break;
        }
        uint32_t expected = UINT32_C(0xA5100000) | (addr >> 16);
        uint32_t observed = 0;
        /* Using memcpy avoids aliasing/alignment assumptions. */
        memcpy(region + addr, &expected, sizeof expected);
        memcpy(&observed, region + addr, sizeof observed);
        if (observed != expected) {
            result = fail(out, n, "32-bit guest address readback", 0);
            break;
        }
        if (mprotect(region + page_base, (size_t)ps, PROT_NONE) != 0) {
            result = fail(out, n, "decommit guest VM page", errno);
            break;
        }
    }
    if (munmap(region, (size_t)GSZ) != 0 && result == 0) {
        result = fail(out, n, "release guest virtual address space", errno);
    }
    return result;
}

int nfs_guest_smoke_run(char *diagnostics, size_t diagnostics_capacity) {
    if (diagnostics == NULL || diagnostics_capacity == 0) return 1;
    diagnostics[0] = '\0';
    if (sizeof(uintptr_t) != 8u) {
        return fail(diagnostics, diagnostics_capacity, "host must be 64-bit", 0);
    }
    if (test_x86_cpu(diagnostics, diagnostics_capacity)) return 1;
    long page_size = 0;
    if (test_guest_address_space(diagnostics, diagnostics_capacity, &page_size)) return 1;

    (void)snprintf(diagnostics, diagnostics_capacity,
                   "PASS | upstream x86 CPU + EFLAGS tests | x87/MMX/XMM storage | "
                   "4 GiB VM reservation | three 32-bit guest pages read/write | "
                   "host page size %ld KiB | no game code executed",
                   page_size / 1024);
    return 0;
}
