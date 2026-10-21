#include "guest_toolhelp.h"
#include "guest_memory.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(_MSC_VER) && !defined(__clang__)
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#define GUEST_TOOLHELP_DEFAULT_PID 100u
#define GUEST_TOOLHELP_DEFAULT_PRI_CLASS_BASE 8

_Static_assert(sizeof(GuestProcessEntry32) == GUEST_PROCESSENTRY32_SIZE,
               "GuestProcessEntry32 size mismatch");

static int set_teb_last_error(CPU *cpu, uint32_t err, uint32_t *fault)
{
    if (!cpu || cpu->fs_base == 0) {
        if (fault) *fault = 0;
        return -2;
    }

    const uint64_t teb_sum = (uint64_t)cpu->fs_base + 0x34ULL;
    if (teb_sum > (uint64_t)UINT32_MAX) {
        if (fault) *fault = UINT32_MAX;
        return -1;
    }

    void *teb_ptr = guest_memory_pointer((uint32_t)teb_sum, 4ULL, 1);
    if (!teb_ptr) {
        if (fault) *fault = (uint32_t)teb_sum;
        return -1;
    }

    memcpy(teb_ptr, &err, sizeof(uint32_t));
    return 0;
}

void guest_toolhelp_init(GuestToolhelpSet *set)
{
    if (set) {
        memset(set, 0, sizeof(*set));
    }
}

void guest_toolhelp_cleanup(GuestToolhelpSet *set)
{
    if (set) {
        memset(set, 0, sizeof(*set));
    }
}

/* Validate host-owned bookkeeping before trusting handles or changing it.
 * A valid active row is tied to its fixed slot, the single guest process, and
 * the two reachable enumeration states (before/after its one process row). */
static int toolhelp_state_is_valid(const GuestToolhelpSet *toolhelp)
{
    if (!toolhelp || toolhelp->count > GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        return 0;
    }

    uint32_t active_count = 0u;
    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; ++i) {
        const GuestToolhelpSnapshot *snap = &toolhelp->snapshots[i];
        if (snap->active == 0u) {
            if (snap->handle != 0u || snap->process_id != 0u || snap->iter_index != 0u) {
                return 0;
            }
            continue;
        }
        if (snap->active != 1u ||
            snap->handle != GUEST_TOOLHELP_HANDLE_BASE + i + 1u ||
            snap->process_id != GUEST_TOOLHELP_DEFAULT_PID ||
            snap->iter_index > 1u) {
            return 0;
        }
        active_count++;
    }
    return active_count == toolhelp->count;
}

static int toolhelp_state_fault(uint32_t *fault)
{
    if (fault) *fault = 0u;
    return -2;
}

int guest_toolhelp_close_handle(CPU *cpu, GuestToolhelpSet *toolhelp, uint32_t handle, uint32_t *fault)
{
    if (!cpu || !toolhelp || !fault) {
        return 0;
    }

    if (handle < GUEST_TOOLHELP_HANDLE_BASE + 1u ||
        handle > GUEST_TOOLHELP_HANDLE_BASE + GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        return 0;
    }

    if (!toolhelp_state_is_valid(toolhelp)) {
        return toolhelp_state_fault(fault);
    }

    uint32_t slot = (handle - GUEST_TOOLHELP_HANDLE_BASE) - 1u;
    GuestToolhelpSnapshot *snap = &toolhelp->snapshots[slot];

    if (snap->active && snap->handle == handle) {
        snap->active = 0u;
        snap->handle = 0u;
        snap->process_id = 0u;
        snap->iter_index = 0u;
        if (toolhelp->count > 0u) {
            toolhelp->count--;
        }
        cpu->eax = 1u;
        return 1;
    }

    int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
    if (err_rc) return err_rc;
    cpu->eax = 0u;
    return 1;
}

static int handle_create_toolhelp32_snapshot(CPU *cpu, GuestToolhelpSet *toolhelp, uint32_t *fault)
{
    if ((uint64_t)cpu->esp + 12ULL > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t frame[3];
    memcpy(frame, frame_ptr, sizeof(frame));
    uint32_t ret_ip = frame[0];
    uint32_t dwFlags = frame[1];
    /* th32ProcessID is ignored for a process-only snapshot. */

    /* This bounded implementation supports only process snapshots, optionally
     * inheritable. Other flags may be valid Win32 requests, so leave them
     * unsupported for the strict dispatcher instead of returning fake results. */
    if (dwFlags != GUEST_TH32CS_SNAPPROCESS &&
        dwFlags != (GUEST_TH32CS_SNAPPROCESS | GUEST_TH32CS_INHERIT)) {
        return 0;
    }

    if (!toolhelp_state_is_valid(toolhelp)) {
        return toolhelp_state_fault(fault);
    }

    /* Check capacity */
    if (toolhelp->count >= GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_HANDLE_VALUE;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* Find first inactive slot */
    uint32_t slot = GUEST_TOOLHELP_SNAPSHOT_LIMIT;
    for (uint32_t i = 0; i < GUEST_TOOLHELP_SNAPSHOT_LIMIT; ++i) {
        if (!toolhelp->snapshots[i].active) {
            slot = i;
            break;
        }
    }

    if (slot >= GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc) return err_rc;
        cpu->eax = GUEST_INVALID_HANDLE_VALUE;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    uint32_t handle = GUEST_TOOLHELP_HANDLE_BASE + slot + 1u;
    toolhelp->snapshots[slot].handle = handle;
    toolhelp->snapshots[slot].process_id = GUEST_TOOLHELP_DEFAULT_PID;
    toolhelp->snapshots[slot].iter_index = 0u;
    toolhelp->snapshots[slot].active = 1u;
    toolhelp->count++;

    cpu->eax = handle;
    cpu->eip = ret_ip;
    cpu->esp += 12u;
    return 1;
}

static int handle_process32_first(CPU *cpu, GuestToolhelpSet *toolhelp, uint32_t *fault)
{
    if ((uint64_t)cpu->esp + 12ULL > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t frame[3];
    memcpy(frame, frame_ptr, sizeof(frame));
    uint32_t ret_ip = frame[0];
    uint32_t hSnapshot = frame[1];
    uint32_t lppe = frame[2];

    if (!toolhelp_state_is_valid(toolhelp)) {
        return toolhelp_state_fault(fault);
    }

    /* Lookup snapshot by handle */
    GuestToolhelpSnapshot *snap = NULL;
    if (hSnapshot >= GUEST_TOOLHELP_HANDLE_BASE + 1u &&
        hSnapshot <= GUEST_TOOLHELP_HANDLE_BASE + GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        uint32_t slot = (hSnapshot - GUEST_TOOLHELP_HANDLE_BASE) - 1u;
        if (toolhelp->snapshots[slot].active && toolhelp->snapshots[slot].handle == hSnapshot) {
            snap = &toolhelp->snapshots[slot];
        }
    }

    if (!snap) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0u;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* Check lppe pointer and read dwSize */
    if ((uint64_t)lppe + 4ULL > 0x100000000ULL) {
        *fault = lppe;
        return -1;
    }

    const void *size_ptr = guest_memory_pointer(lppe, 4ULL, 0);
    if (!size_ptr) {
        *fault = lppe;
        return -1;
    }

    uint32_t dwSize = 0u;
    memcpy(&dwSize, size_ptr, sizeof(uint32_t));
    if (dwSize < GUEST_PROCESSENTRY32_SIZE) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0u;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* Validate write pointer for 296 bytes */
    if ((uint64_t)lppe + (uint64_t)GUEST_PROCESSENTRY32_SIZE > 0x100000000ULL) {
        *fault = lppe;
        return -1;
    }

    void *dest_ptr = guest_memory_pointer(lppe, (uint64_t)GUEST_PROCESSENTRY32_SIZE, 1);
    if (!dest_ptr) {
        *fault = lppe;
        return -1;
    }

    snap->iter_index = 0u;

    GuestProcessEntry32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = GUEST_PROCESSENTRY32_SIZE;
    pe.cntUsage = 0u;
    pe.th32ProcessID = snap->process_id;
    pe.th32DefaultHeapID = 0u;
    pe.th32ModuleID = 0u;
    pe.cntThreads = 1u;
    pe.th32ParentProcessID = 0u;
    pe.pcPriClassBase = GUEST_TOOLHELP_DEFAULT_PRI_CLASS_BASE;
    pe.dwFlags = 0u;
    memcpy(pe.szExeFile, "SPEED2.EXE", sizeof("SPEED2.EXE"));

    memcpy(dest_ptr, &pe, sizeof(pe));

    snap->iter_index = 1u;
    cpu->eax = 1u;
    cpu->eip = ret_ip;
    cpu->esp += 12u;
    return 1;
}

static int handle_process32_next(CPU *cpu, GuestToolhelpSet *toolhelp, uint32_t *fault)
{
    if ((uint64_t)cpu->esp + 12ULL > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    const void *frame_ptr = guest_memory_pointer(cpu->esp, 12ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t frame[3];
    memcpy(frame, frame_ptr, sizeof(frame));
    uint32_t ret_ip = frame[0];
    uint32_t hSnapshot = frame[1];
    uint32_t lppe = frame[2];

    if (!toolhelp_state_is_valid(toolhelp)) {
        return toolhelp_state_fault(fault);
    }

    /* Lookup snapshot by handle */
    GuestToolhelpSnapshot *snap = NULL;
    if (hSnapshot >= GUEST_TOOLHELP_HANDLE_BASE + 1u &&
        hSnapshot <= GUEST_TOOLHELP_HANDLE_BASE + GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
        uint32_t slot = (hSnapshot - GUEST_TOOLHELP_HANDLE_BASE) - 1u;
        if (toolhelp->snapshots[slot].active && toolhelp->snapshots[slot].handle == hSnapshot) {
            snap = &toolhelp->snapshots[slot];
        }
    }

    if (!snap) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INVALID_HANDLE, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0u;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* Validate lppe and read dwSize */
    if ((uint64_t)lppe + 4ULL > 0x100000000ULL) {
        *fault = lppe;
        return -1;
    }

    const void *size_ptr = guest_memory_pointer(lppe, 4ULL, 0);
    if (!size_ptr) {
        *fault = lppe;
        return -1;
    }

    uint32_t dwSize = 0u;
    memcpy(&dwSize, size_ptr, sizeof(uint32_t));
    if (dwSize < GUEST_PROCESSENTRY32_SIZE) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0u;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* If iter_index >= 1: no more processes */
    if (snap->iter_index >= 1u) {
        int err_rc = set_teb_last_error(cpu, GUEST_ERROR_NO_MORE_FILES, fault);
        if (err_rc) return err_rc;
        cpu->eax = 0u;
        cpu->eip = ret_ip;
        cpu->esp += 12u;
        return 1;
    }

    /* If iter_index == 0: provide first process entry */
    if ((uint64_t)lppe + (uint64_t)GUEST_PROCESSENTRY32_SIZE > 0x100000000ULL) {
        *fault = lppe;
        return -1;
    }

    void *dest_ptr = guest_memory_pointer(lppe, (uint64_t)GUEST_PROCESSENTRY32_SIZE, 1);
    if (!dest_ptr) {
        *fault = lppe;
        return -1;
    }

    GuestProcessEntry32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = GUEST_PROCESSENTRY32_SIZE;
    pe.cntUsage = 0u;
    pe.th32ProcessID = snap->process_id;
    pe.cntThreads = 1u;
    pe.pcPriClassBase = GUEST_TOOLHELP_DEFAULT_PRI_CLASS_BASE;
    memcpy(pe.szExeFile, "SPEED2.EXE", sizeof("SPEED2.EXE"));

    memcpy(dest_ptr, &pe, sizeof(pe));

    snap->iter_index = 1u;
    cpu->eax = 1u;
    cpu->eip = ret_ip;
    cpu->esp += 12u;
    return 1;
}

int guest_toolhelp_import(CPU *cpu, const GuestImport *import, GuestToolhelpSet *toolhelp, uint32_t *fault)
{
    if (!cpu || !import || !import->library || !import->name || !toolhelp || !fault) {
        return 0;
    }

    if (strcasecmp(import->library, "KERNEL32.dll") != 0) {
        return 0;
    }

    if (strcmp(import->name, "CreateToolhelp32Snapshot") == 0) {
        return handle_create_toolhelp32_snapshot(cpu, toolhelp, fault);
    }

    if (strcmp(import->name, "Process32First") == 0) {
        return handle_process32_first(cpu, toolhelp, fault);
    }

    if (strcmp(import->name, "Process32Next") == 0) {
        return handle_process32_next(cpu, toolhelp, fault);
    }

    if (strcmp(import->name, "CloseHandle") == 0) {
        if ((uint64_t)cpu->esp + 8ULL > 0x100000000ULL) {
            *fault = cpu->esp;
            return -1;
        }

        const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
        if (!frame_ptr) {
            *fault = cpu->esp;
            return -1;
        }

        uint32_t frame[2];
        memcpy(frame, frame_ptr, sizeof(frame));
        uint32_t ret_ip = frame[0];
        uint32_t handle = frame[1];

        /* Only handle toolhelp snapshot handles; leave other ranges for other subsystems */
        if (handle < GUEST_TOOLHELP_HANDLE_BASE + 1u ||
            handle > GUEST_TOOLHELP_HANDLE_BASE + GUEST_TOOLHELP_SNAPSHOT_LIMIT) {
            return 0;
        }

        int rc = guest_toolhelp_close_handle(cpu, toolhelp, handle, fault);
        if (rc == 1) {
            cpu->eip = ret_ip;
            cpu->esp += 8u;
            return 1;
        }
        return rc;
    }

    return 0;
}
