#ifndef NFSU2_GUEST_TOOLHELP_H
#define NFSU2_GUEST_TOOLHELP_H

#include "guest_execution.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GUEST_TOOLHELP_HANDLE_BASE      0x00D10000u
#define GUEST_TOOLHELP_SNAPSHOT_LIMIT   8u
#define GUEST_PROCESSENTRY32_SIZE       296u

#ifndef GUEST_INVALID_HANDLE_VALUE
#define GUEST_INVALID_HANDLE_VALUE      0xFFFFFFFFu
#endif

#ifndef GUEST_ERROR_INVALID_HANDLE
#define GUEST_ERROR_INVALID_HANDLE      6u
#endif
#ifndef GUEST_ERROR_NO_MORE_FILES
#define GUEST_ERROR_NO_MORE_FILES       18u
#endif
#ifndef GUEST_ERROR_INVALID_PARAMETER
#define GUEST_ERROR_INVALID_PARAMETER   87u
#endif
#ifndef GUEST_ERROR_INSUFFICIENT_BUFFER
#define GUEST_ERROR_INSUFFICIENT_BUFFER 122u
#endif

#ifndef GUEST_TH32CS_SNAPPROCESS
#define GUEST_TH32CS_SNAPPROCESS        0x00000002u
#endif
#ifndef GUEST_TH32CS_INHERIT
#define GUEST_TH32CS_INHERIT            0x80000000u
#endif

typedef struct GuestToolhelpSnapshot {
    uint32_t handle;
    /* The current profile exposes only its single guest process (PID 100). */
    uint32_t process_id;
    /* 0 before the row is returned; 1 after it has been returned. */
    uint32_t iter_index;
    uint32_t active;
} GuestToolhelpSnapshot;

typedef struct GuestToolhelpSet {
    GuestToolhelpSnapshot snapshots[GUEST_TOOLHELP_SNAPSHOT_LIMIT];
    /* Must equal the number of canonical active slots. */
    uint32_t count;
} GuestToolhelpSet;

typedef struct GuestProcessEntry32 {
    uint32_t dwSize;
    uint32_t cntUsage;
    uint32_t th32ProcessID;
    uint32_t th32DefaultHeapID;
    uint32_t th32ModuleID;
    uint32_t cntThreads;
    uint32_t th32ParentProcessID;
    int32_t  pcPriClassBase;
    uint32_t dwFlags;
    char     szExeFile[260];
} GuestProcessEntry32;

void guest_toolhelp_init(GuestToolhelpSet *set);
void guest_toolhelp_cleanup(GuestToolhelpSet *set);
int guest_toolhelp_import(CPU *cpu, const GuestImport *import, GuestToolhelpSet *toolhelp, uint32_t *fault);
int guest_toolhelp_close_handle(CPU *cpu, GuestToolhelpSet *toolhelp, uint32_t handle, uint32_t *fault);

#ifdef __cplusplus
}
#endif

#endif /* NFSU2_GUEST_TOOLHELP_H */
