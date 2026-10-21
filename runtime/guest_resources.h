#ifndef NFSU2_GUEST_RESOURCES_H
#define NFSU2_GUEST_RESOURCES_H

#include "guest_execution.h"
#include "guest_pe.h"

/* Narrow native-resource policy for the loaded PE32 image. Returns 1 for a
 * completed stdcall, 0 when the call is outside the supported policy,
 * -1 for an inaccessible guest-memory read (fault address returned through
 * fault), or -2 for an invalid host execution state such as a missing TEB.
 * Malformed but readable resource metadata is unsupported and leaves state
 * untouched. */
int guest_resources_import(CPU *cpu, const GuestImport *import,
                           const GuestPEImage *image, uint32_t *fault);

#endif
