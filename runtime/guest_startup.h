#ifndef NFSU2_GUEST_STARTUP_H
#define NFSU2_GUEST_STARTUP_H
#include "guest_execution.h"
/* Configured XP x86 GUI process startup: STARTUPINFOA is 68 bytes, cb=68,
 * remaining fields zero, dwFlags=0 (no inherited std handles/CRT reserved data).
 * This is deliberate virtual-process configuration, not host Windows state.
 * GetStartupInfoA is void: preserve EAX, flags and LastError. One stdcall arg.
 * Validate the entire writable output before mutation; snapshot ret/arg first.
 * Invalid/null output is a strict guest memory stop, not fabricated API success.
 * Same handler result contract as GuestImportHandler; no native resources. */
int guest_startup_import(CPU *, const GuestImport *, uint32_t *fault);
#endif
