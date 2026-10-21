#ifndef NFSU2_GUEST_REGISTRY_H
#define NFSU2_GUEST_REGISTRY_H

#include "guest_execution.h"

/* Authored, read-only empty registry profile for the startup probe.
 * The five predefined roots exist, but no nonempty subkey exists and the host
 * registry is never queried. Return contract matches GuestImportHandler. */
int guest_registry_import(CPU *cpu, const GuestImport *imp, uint32_t *fault);

#endif /* NFSU2_GUEST_REGISTRY_H */
