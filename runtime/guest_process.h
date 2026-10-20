#ifndef NFSU2_GUEST_PROCESS_H
#define NFSU2_GUEST_PROCESS_H
#include "guest_execution.h"
#define GUEST_PROCESS_BASE 0x00c20000u
#define GUEST_PROCESS_RESERVED 0x10000u
#define GUEST_PROCESS_BYTES 0x4000u
#define GUEST_PROCESS_COMMAND GUEST_PROCESS_BASE
#define GUEST_PROCESS_ENV_A (GUEST_PROCESS_BASE+0x1000u)
#define GUEST_PROCESS_ENV_W (GUEST_PROCESS_BASE+0x2000u)
#define GUEST_PROCESS_ENV_LEASES 32u
#define GUEST_PROCESS_COMMAND_LINE "C:\\NFSU2\\SPEED2.EXE"
typedef struct GuestProcess {
    uint32_t initialized, environment_a_refs, environment_w_refs;
} GuestProcess;
/* Zero-init metadata; exclusive ownership of reserved c20000-c30000 required.
 * Call after bootstrap on a fresh VM before guest execution/thread allocation.
 * Validate image nonempty/in 4GiB/nonoverlap with the entire reservation, reject
 * duplicate init and existing accessible granules there BEFORE mutation.
 * Commit only first16KiB, zero it, copy canonical ASCII command line incl NUL.
 * Empty narrow/OEM env is two NUL bytes; wide env two zero UTF16 code units.
 * No host environment or host paths. API callers treat returned strings as
 * immutable; mapping stays RW for the current bounded typed-access lifter.
 * OS commit failure may leave owned pages; metadata stays uninitialized and
 * owner disposes entire VM. Cleanup only zeroes metadata, safe after shutdown.
 * Addresses must be reserved away from any future guest-thread TEB allocator. */
int guest_process_init(GuestProcess *, const GuestPEImage *);
void guest_process_cleanup(GuestProcess *);
/* KERNEL32.dll case-insensitive; exact GetCommandLineA/GetEnvironmentStrings/
 * GetEnvironmentStringsW/FreeEnvironmentStringsA/W/GetACP/GetOEMCP only.
 * GetCommandLineA: argc0, stable COMMAND pointer. ACP1252/OEM437: argc0.
 * Env getters: argc0, stable per-encoding pointer; increment that encoding's
 * outstanding lease count (max32). Cap => NULL result, guest LastError8 after
 * TEB write preflight. Normal success preserves LastError. Each matching free
 * argc1 validates exact pointer + outstanding count, decrements and returns1;
 * wrong/duplicate free => strict API_STATE (-2), no frame/count mutation.
 * Values are configured guest process state, not host Windows success stubs.
 * Unknown/malformed host args or null process context =>0 unchanged. Known API
 * on uninitialized state =>-2 fault PROCESS_BASE. Snapshot readable whole frame
 * before all writes; validate returned strings remain readable (full command
 * incl NUL; A2/W4 bytes); bad memory/overflow =>-1, no CPU/count/output changes.
 * Cap error needs nonzero fs_base (-2 if0), uint64(fs)+34 writable, fault max if
 * sum overflows. Success EAXresult/EIPret/ESP+4*(argc+1), preserve all else.
 * Caller serializes calls, process leases and all VM lifecycle operations. */
int guest_process_import(CPU *, const GuestImport *, GuestProcess *, uint32_t *fault);
#endif
