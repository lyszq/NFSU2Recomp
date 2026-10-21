#include "guest_user_objects.h"

#include "guest_memory.h"

#include <string.h>
#include <strings.h>

#define LOADCURSORA_FRAME_SIZE 12u

static int is_arrow_descriptor(const GuestUserObject *object)
{
    return object->handle != 0u &&
           object->type == GUEST_USER_OBJECT_CURSOR &&
           object->source == GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED &&
           object->module == 0u &&
           object->resource_id == GUEST_USER_OBJECT_IDC_ARROW &&
           object->shared == 1u;
}

static int objects_are_consistent(const GuestUserObjects *objects)
{
    if (!objects || objects->count > GUEST_USER_OBJECT_LIMIT) return 0;

    uint32_t used = 0u;
    for (uint32_t i = 0; i < GUEST_USER_OBJECT_LIMIT; ++i) {
        const GuestUserObject *object = &objects->entries[i];
        if (!object->handle) continue;
        ++used;
        if (object->handle != GUEST_USER_OBJECT_HANDLE_BASE + i + 1u ||
            (object->type != GUEST_USER_OBJECT_ICON &&
             object->type != GUEST_USER_OBJECT_CURSOR) ||
            (object->source != GUEST_USER_OBJECT_SOURCE_PE_IMAGE &&
             object->source != GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED) ||
            object->shared > 1u ||
            (object->source == GUEST_USER_OBJECT_SOURCE_PE_IMAGE &&
             !object->module) ||
            (object->source == GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED &&
             (object->module || !object->shared))) {
            return 0;
        }
    }
    return used == objects->count;
}

const GuestUserObject *guest_user_objects_lookup(
    const GuestUserObjects *objects, uint32_t handle,
    GuestUserObjectType expected_type)
{
    if (!handle || !objects_are_consistent(objects) ||
        (expected_type != GUEST_USER_OBJECT_ICON &&
         expected_type != GUEST_USER_OBJECT_CURSOR)) {
        return NULL;
    }

    for (uint32_t i = 0; i < GUEST_USER_OBJECT_LIMIT; ++i) {
        const GuestUserObject *object = &objects->entries[i];
        if (object->handle == handle && object->type == expected_type) {
            return object;
        }
    }
    return NULL;
}

int guest_user_objects_import(CPU *cpu, const GuestImport *import,
                              GuestUserObjects *objects, uint32_t *fault)
{
    if (!cpu || !import || !import->library || !import->name || !objects ||
        !fault) {
        return 0;
    }
    if (strcasecmp(import->library, "USER32.dll") != 0 ||
        strcmp(import->name, "LoadCursorA") != 0) {
        return 0;
    }

    const uint8_t *frame_bytes = (const uint8_t *)guest_memory_pointer(
        cpu->esp, LOADCURSORA_FRAME_SIZE, 0);
    if (!frame_bytes) {
        *fault = cpu->esp;
        return -1;
    }

    /* Snapshot the full stdcall frame before changing the descriptor table or
     * CPU, including when the stack is unaligned. */
    uint32_t frame[3];
    memcpy(frame, frame_bytes, sizeof(frame));
    const uint32_t return_ip = frame[0];
    const uint32_t module = frame[1];
    const uint32_t cursor_name = frame[2];

    /* The only measured success is the shared system arrow. Module resources,
     * other system cursor IDs, and string names are outside this contract. */
    if (module != 0u || cursor_name != GUEST_USER_OBJECT_IDC_ARROW ||
        !objects_are_consistent(objects)) {
        return 0;
    }

    GuestUserObject *arrow = NULL;
    uint32_t first_free = GUEST_USER_OBJECT_LIMIT;
    for (uint32_t i = 0; i < GUEST_USER_OBJECT_LIMIT; ++i) {
        GuestUserObject *candidate = &objects->entries[i];
        if (!candidate->handle) {
            if (first_free == GUEST_USER_OBJECT_LIMIT) first_free = i;
            continue;
        }
        if (candidate->type == GUEST_USER_OBJECT_CURSOR &&
            candidate->source == GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED &&
            candidate->module == 0u &&
            candidate->resource_id == GUEST_USER_OBJECT_IDC_ARROW) {
            if (!is_arrow_descriptor(candidate) || arrow) return 0;
            arrow = candidate;
        }
    }

    if (!arrow) {
        if (first_free == GUEST_USER_OBJECT_LIMIT) return 0;
        const uint32_t handle = GUEST_USER_OBJECT_HANDLE_BASE + first_free + 1u;
        if (!handle) return 0;
        arrow = &objects->entries[first_free];
        *arrow = (GuestUserObject){
            .handle = handle,
            .type = GUEST_USER_OBJECT_CURSOR,
            .source = GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED,
            .module = 0u,
            .resource_id = GUEST_USER_OBJECT_IDC_ARROW,
            .shared = 1u,
        };
        ++objects->count;
    }

    /* LoadCursorA preserves LastError. The opaque token is scoped to this
     * GuestUserObjects table and resolves only as a CURSOR descriptor. */
    cpu->eax = arrow->handle;
    cpu->eip = return_ip;
    cpu->esp += LOADCURSORA_FRAME_SIZE;
    return 1;
}

void guest_user_objects_cleanup(GuestUserObjects *objects)
{
    if (objects) memset(objects, 0, sizeof(*objects));
}
