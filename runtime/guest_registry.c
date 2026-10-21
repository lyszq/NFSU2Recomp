#include "guest_registry.h"
#include "guest_memory.h"

#include <stdint.h>
#include <string.h>
#include <strings.h>

#define REGOPENKEYA_FRAME_SIZE 16U
#define REGOPENKEYA_SUBKEY_SCAN_LIMIT 4096U

#define ERROR_FILE_NOT_FOUND 2U
#define ERROR_INVALID_HANDLE 6U

#define HKEY_CLASSES_ROOT  UINT32_C(0x80000000)
#define HKEY_CURRENT_USER  UINT32_C(0x80000001)
#define HKEY_LOCAL_MACHINE UINT32_C(0x80000002)
#define HKEY_USERS         UINT32_C(0x80000003)
#define HKEY_CURRENT_CONFIG UINT32_C(0x80000005)

/* Fixed frame/output range faults identify the requested base, matching the
 * other guest import handlers. String faults identify the first bad byte. */
static int checked_guest_pointer(uint32_t address, uint64_t size,
                                 int write_access, void **pointer,
                                 uint32_t *fault)
{
    void *resolved = guest_memory_pointer(address, size, write_access);
    if (resolved) {
        *pointer = resolved;
        return 0;
    }

    *fault = address;
    return -1;
}

static int is_predefined_root(uint32_t key)
{
    return key == HKEY_CLASSES_ROOT || key == HKEY_CURRENT_USER ||
           key == HKEY_LOCAL_MACHINE || key == HKEY_USERS ||
           key == HKEY_CURRENT_CONFIG;
}

/* Return 1 when the bounded string was read, 0 when it is unsupported because
 * it exceeds the limit, and -1 for a guest-memory fault. Only the empty/nonempty
 * distinction is needed by this intentionally empty namespace; scanning all
 * bytes before output ensures result-pointer aliases cannot change the answer. */
static int inspect_subkey(uint32_t address, int *nonempty, uint32_t *fault)
{
    *nonempty = 0;
    if (address == 0U) {
        return 1;
    }

    for (uint64_t offset = 0U; offset < REGOPENKEYA_SUBKEY_SCAN_LIMIT; offset++) {
        const uint64_t current = (uint64_t)address + offset;
        if (current > UINT32_MAX) {
            *fault = UINT32_MAX;
            return -1;
        }

        const uint8_t *byte = (const uint8_t *)guest_memory_pointer(
            (uint32_t)current, 1U, 0);
        if (!byte) {
            *fault = (uint32_t)current;
            return -1;
        }
        if (*byte == 0U) {
            *nonempty = offset != 0U;
            return 1;
        }
    }

    /* More than 4095 bytes without a terminator is outside this probe's
     * bounded contract. Leave guest CPU and memory untouched. */
    return 0;
}

int guest_registry_import(CPU *cpu, const GuestImport *imp, uint32_t *fault)
{
    if (!cpu || !imp || !fault || !imp->library || !imp->name) {
        return 0;
    }
    if (strcasecmp(imp->library, "ADVAPI32.dll") != 0 ||
        strcmp(imp->name, "RegOpenKeyA") != 0) {
        return 0;
    }

    void *frame_pointer = NULL;
    if (checked_guest_pointer(cpu->esp, REGOPENKEYA_FRAME_SIZE, 0,
                              &frame_pointer, fault) != 0) {
        return -1;
    }

    /* Snapshot every argument before validating or writing the output. */
    uint32_t frame[4];
    memcpy(frame, frame_pointer, sizeof(frame));
    const uint32_t ret_ip = frame[0];
    const uint32_t root = frame[1];
    const uint32_t subkey_address = frame[2];
    const uint32_t result_address = frame[3];

    int nonempty = 0;
    const int inspect_status = inspect_subkey(subkey_address, &nonempty, fault);
    if (inspect_status < 0) return -1;
    if (inspect_status == 0) return 0;

    if (result_address == 0U) {
        *fault = 0U;
        return -1;
    }

    void *result_pointer = NULL;
    if (checked_guest_pointer(result_address, sizeof(uint32_t), 1,
                              &result_pointer, fault) != 0) {
        return -1;
    }

    uint32_t status = 0U;
    uint32_t result = 0U;
    if (!is_predefined_root(root)) {
        status = ERROR_INVALID_HANDLE;
    } else {
        if (nonempty) {
            status = ERROR_FILE_NOT_FOUND;
        } else {
            result = root;
        }
    }

    memcpy(result_pointer, &result, sizeof(result));
    cpu->eax = status;
    cpu->eip = ret_ip;
    cpu->esp += REGOPENKEYA_FRAME_SIZE;
    return 1;
}
