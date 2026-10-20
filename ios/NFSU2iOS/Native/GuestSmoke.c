/* Native CPU ABI and the SAME guest-memory core used by desktop mem.c.
 * Test instructions below are handwritten ABI probes, never lifted game code. */
#include "GuestSmoke.h"
#include "../../../runtime/cpu.h"
#include "../../../runtime/guest_memory.h"
#include "../../tests/cpu_flags_test.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int fail(char *out, size_t n, const char *phase, int err) {
    (void)snprintf(out, n, "FAIL | %s | error=%d (%s) | no game code executed",
                   phase, err, err ? strerror(err) : "assertion");
    return 1;
}

static int test_guest_memory(char *out, size_t n, size_t *page_size) {
    int rc = guest_memory_init();
    if (rc) return fail(out, n, "shared core reserve 4 GiB", rc);
    *page_size = guest_memory_host_page_size();
    int result = 0;
#define CHECK(test, phase) do { if (!(test)) { result = fail(out, n, phase, 0); goto done; } } while (0)
#define CALL(call, phase) do { rc = (call); if (rc) { result = fail(out, n, phase, rc); goto done; } } while (0)
    CHECK(GSZ == GUEST_MEMORY_SIZE, "guest address ABI size");
    CHECK(guest_memory_pointer(0x400040u, 4, 0) == NULL, "uncommitted range rejected");
    const uint32_t addresses[] = {0x00400040u, 0x10000040u, 0xf0000040u, 0xfffffffcu};
    for (unsigned i = 0; i < sizeof addresses / sizeof addresses[0]; ++i) {
        uint32_t addr = addresses[i];
        CALL(guest_memory_commit(addr, 4), "shared core commit");
        CHECK(mem_is_committed(addr), "cpu.h bitmap matches core");
        CHECK(guest_memory_pointer(addr, 4, 1) == g_mem + addr, "checked offset translation");
        MR32(addr) = 0xa5100000u + i;
    }
    /* Volatile reads verify actual storage and rule out aliasing across guest ranges. */
    for (unsigned i = 0; i < sizeof addresses / sizeof addresses[0]; ++i) {
        CHECK(*(volatile uint32_t *)(g_mem + addresses[i]) == 0xa5100000u + i,
              "distinct 32-bit guest address readback");
    }
    const uint64_t bytes = guest_memory_committed();
    CALL(guest_memory_commit(addresses[0], 4), "overlapping commit");
    CALL(guest_memory_commit(0xffffffffu, 0), "zero length no-op");
    CHECK(guest_memory_committed() == bytes, "unique page accounting");
    CHECK(guest_memory_commit(0xfffffffcu, 8) == EOVERFLOW, "reject 32-bit range wrap");
    CHECK(guest_memory_commit(1u, UINT64_MAX) == EOVERFLOW, "reject 64-bit length overflow");
    CHECK(guest_memory_pointer(0xfffffffcu, 8, 0) == NULL, "reject wrapped translation");
    CHECK(guest_memory_pointer(0x003fffffu, 2, 0) == NULL, "reject partially committed range");
    CALL(guest_memory_protect(addresses[0], 4, GUEST_MEMORY_READ), "read-only protection");
    CHECK(guest_memory_pointer(addresses[0], 4, 0) != NULL &&
          guest_memory_pointer(addresses[0], 4, 1) == NULL, "read-only checked permissions");
    CALL(guest_memory_protect(addresses[0], 4, GUEST_MEMORY_NONE), "no-access protection");
    CHECK(!mem_is_committed(addresses[0]) &&
          guest_memory_pointer(addresses[0], 4, 0) == NULL, "no-access bitmap and translation");
    CALL(guest_memory_commit(addresses[0], 4), "restore guest RW page");
    CHECK(MR32(addresses[0]) == 0xa5100000u && guest_memory_committed() == bytes,
          "protection restore preserves contents and count");

    CPU context = {0};
    CPU *c = &context;
    CALL(guest_memory_commit(0x20000000u, 0x8000u), "CPU stack pages");
    c->esp = 0x20004004u;
    PUSH32(c->esp); /* Must evaluate source before updating ESP. */
    PUSH32(0x11223344u);
    POP32(c->eax);
    POP32(c->ebx);
    CHECK(c->eax == 0x11223344u && c->ebx == 0x20004004u && c->esp == 0x20004004u,
          "upstream PUSH/POP across guest page boundary");
    c->esp = 4u;
    CALL(guest_memory_commit(0u, 4), "low guest page");
    PUSH32(0x12345678u);
    POP32(c->ecx);
    CHECK(c->ecx == 0x12345678u && c->esp == 4u, "guest address zero is valid offset");
    c->esp = 0u;
    PUSH32(0x87654321u); /* x86 register arithmetic wraps; memory range does not. */
    CHECK(c->esp == 0xfffffffcu && MR32(c->esp) == 0x87654321u, "32-bit ESP wrap");
    POP32(c->edx);
    CHECK(c->esp == 0u && c->edx == 0x87654321u, "POP restores wrapped ESP");
    c->st[0] = 1.5;
    c->mm[0] = UINT64_C(0x1234567887654321);
    c->xmm[0].u32[0] = 0xdeadbeefu;
    CHECK(c->st[0] == 1.5 && c->mm[0] == UINT64_C(0x1234567887654321) &&
          c->xmm[0].u32[0] == 0xdeadbeefu, "x87/MMX/XMM storage");
done:
    rc = guest_memory_shutdown();
    if (rc && !result) result = fail(out, n, "shared core release", rc);
    if (!result && (g_mem || guest_memory_committed() || mem_is_committed(0)))
        result = fail(out, n, "shared core lifecycle reset", 0);
    return result;
#undef CHECK
#undef CALL
}

int nfs_guest_smoke_run(char *diagnostics, size_t capacity) {
    if (!diagnostics || !capacity) return 1;
    diagnostics[0] = '\0';
    if (sizeof(uintptr_t) != 8u) return fail(diagnostics, capacity, "64-bit host required", 0);
    /* Never tear down a live game mapping if a future caller runs this probe. */
    if (g_mem) return fail(diagnostics, capacity, "guest runtime already active", EBUSY);
    if (nfs_cpu_flags_test(diagnostics, capacity)) return 1;
    size_t page_size = 0;
    if (test_guest_memory(diagnostics, capacity, &page_size)) return 1;
    (void)snprintf(diagnostics, capacity,
        "PASS | shared guest_memory.c | upstream CPU/EFLAGS reference tests | "
        "4 GiB VM + low/PE/heap/high/top addresses | protection + overflow checks | "
        "PUSH/POP + ESP wrap | page %zu KiB | no JIT | no game code executed",
        page_size / 1024u);
    return 0;
}
