#ifndef NFSU2_GUEST_WINDOWS_H
#define NFSU2_GUEST_WINDOWS_H
#include "guest_execution.h"
#include "guest_heap.h"
#include "guest_critical.h"
#include "guest_tls.h"
/* Explicit guest Windows XP compatibility policy, independent of the host OS.
 * Only implemented contracts are serviced. No unknown API success fallback.
 * Caller supplies the bootstrap TEB and serializes the guest thread/heap state.
 * No guest thread creation, executable heaps, or exception-generating flags.
 * Main module identity is SPEED2.EXE; extensionless names default to DLL and
 * paths are not resolved without a guest filesystem/module loader. */
typedef struct GuestWindows {
    uint32_t image_base;
    GuestHeapSet heaps;
    GuestCriticalSet critical;
    GuestTLSSet tls;
} GuestWindows;
int guest_windows_import(CPU *cpu, const GuestImport *import, void *context,
                         uint32_t *fault);
/* Quiesced runtime teardown; required even when execution stops or longjmps. */
int guest_windows_cleanup(GuestWindows *);
#endif
