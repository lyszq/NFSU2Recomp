#ifndef NFSU2_GUEST_ERROR_H
#define NFSU2_GUEST_ERROR_H
#include "guest_execution.h"
/* Per-guest-thread LastError at x86 TEB+0x34, never the host's errno/TLS.
 * GetLastError is stdcall argc0, returns stored DWORD. SetLastError is argc1,
 * void and preserves EAX. Both preserve flags and other GPRs. Snapshot all
 * call-frame data and preflight access before mutation. Nonzero TEB required;
 * zero TEB is invalid state (-2); inaccessible/overflowed memory returns -1.
 * Unsupported import/library and malformed host args return 0 unchanged.
 * This helper does not manufacture errors for unrelated unimplemented APIs. */
int guest_error_import(CPU *, const GuestImport *, uint32_t *fault);
#endif
