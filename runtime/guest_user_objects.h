#ifndef NFSU2_GUEST_USER_OBJECTS_H
#define NFSU2_GUEST_USER_OBJECTS_H

#include "guest_execution.h"

#include <stdint.h>

/* Per-GuestWindows table of opaque USER32 resource identities. These are
 * virtual guest handles, not host HICON/HCURSOR values. Consumers must resolve
 * the handle and check its type before using it. */
#define GUEST_USER_OBJECT_LIMIT 8u
#define GUEST_USER_OBJECT_HANDLE_BASE UINT32_C(0x00b10000)
#define GUEST_USER_OBJECT_IDC_ARROW UINT32_C(32512)

typedef enum GuestUserObjectType {
    GUEST_USER_OBJECT_ICON = 1,
    GUEST_USER_OBJECT_CURSOR = 2
} GuestUserObjectType;

typedef enum GuestUserObjectSource {
    GUEST_USER_OBJECT_SOURCE_PE_IMAGE = 1,
    GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED = 2
} GuestUserObjectSource;

typedef struct GuestUserObject {
    uint32_t handle;
    GuestUserObjectType type;
    GuestUserObjectSource source;
    uint32_t module;
    uint32_t resource_id;
    uint32_t shared;
} GuestUserObject;

typedef struct GuestUserObjects {
    GuestUserObject entries[GUEST_USER_OBJECT_LIMIT];
    /* Number of occupied slots; slots may be sparse and are allocated first-free. */
    uint32_t count;
} GuestUserObjects;

/* Handles the measured LoadCursorA(NULL, IDC_ARROW) contract only. Returns 1
 * for a completed stdcall, 0 for unsupported input without mutation, -1 for a
 * guest-memory fault (fault address returned through fault). Success preserves
 * LastError and updates only EAX, EIP, and ESP. */
int guest_user_objects_import(CPU *cpu, const GuestImport *import,
                              GuestUserObjects *objects, uint32_t *fault);

/* Returns a table-backed descriptor only when both handle and expected type
 * match. The pointer remains valid until the set is modified or cleared. */
const GuestUserObject *guest_user_objects_lookup(
    const GuestUserObjects *objects, uint32_t handle,
    GuestUserObjectType expected_type);

/* Clears the process-scoped virtual handles. */
void guest_user_objects_cleanup(GuestUserObjects *objects);

#endif
