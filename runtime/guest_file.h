#ifndef NFSU2_GUEST_FILE_H
#define NFSU2_GUEST_FILE_H

#include "guest_execution.h"
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GUEST_FILE_HANDLE_BASE        UINT32_C(0x00900000)
#define GUEST_FILE_HANDLE_MAX         1024
#define GUEST_VFS_PATH_MAX            260
#define GUEST_VFS_HASH_BUCKETS        4096
#define GUEST_VFS_MAX_SEARCH_ROOTS    8

/* Win32 Creation Disposition */
#define GUEST_CREATE_NEW              1u
#define GUEST_CREATE_ALWAYS           2u
#define GUEST_OPEN_EXISTING           3u
#define GUEST_OPEN_ALWAYS             4u
#define GUEST_TRUNCATE_EXISTING       5u

/* Win32 Desired Access */
#define GUEST_GENERIC_READ            UINT32_C(0x80000000)
#define GUEST_GENERIC_WRITE           UINT32_C(0x40000000)
#define GUEST_GENERIC_EXECUTE         UINT32_C(0x20000000)
#define GUEST_GENERIC_ALL             UINT32_C(0x10000000)

/* Win32 Seek Method */
#define GUEST_FILE_BEGIN              0u
#define GUEST_FILE_CURRENT            1u
#define GUEST_FILE_END                2u

/* Win32 File Attributes */
#define GUEST_FILE_ATTRIBUTE_READONLY         0x00000001u
#define GUEST_FILE_ATTRIBUTE_DIRECTORY        0x00000010u
#define GUEST_FILE_ATTRIBUTE_ARCHIVE          0x00000020u
#define GUEST_FILE_ATTRIBUTE_NORMAL           0x00000080u
#define GUEST_INVALID_FILE_ATTRIBUTES         UINT32_C(0xFFFFFFFF)

/* Win32 Handle & Return Constants */
#define GUEST_INVALID_HANDLE_VALUE            UINT32_C(0xFFFFFFFF)
#define GUEST_INVALID_SET_FILE_POINTER        UINT32_C(0xFFFFFFFF)
#define GUEST_INVALID_FILE_SIZE               UINT32_C(0xFFFFFFFF)

/* Win32 Error Codes (stored at TEB+0x34) */
#define GUEST_ERROR_SUCCESS           0u
#define GUEST_ERROR_FILE_NOT_FOUND    2u
#define GUEST_ERROR_PATH_NOT_FOUND    3u
#define GUEST_ERROR_TOO_MANY_OPEN_FILES 4u
#define GUEST_ERROR_ACCESS_DENIED     5u
#define GUEST_ERROR_INVALID_HANDLE    6u
#define GUEST_ERROR_FILE_EXISTS       80u
#define GUEST_ERROR_INVALID_PARAMETER 87u
#define GUEST_ERROR_NEGATIVE_SEEK     131u
#define GUEST_ERROR_ALREADY_EXISTS    183u

/* Multi-Root Search Priority Levels */
typedef enum GuestVFSRootPriority {
    GUEST_VFS_PRIORITY_WRITE        = 0,  /* Dedicated writable save/profile root */
    GUEST_VFS_PRIORITY_DOCUMENTS    = 1,  /* Priority 1: <Documents>/Game/ (User/mod overrides) */
    GUEST_VFS_PRIORITY_BUNDLE       = 2,  /* Priority 2: <AppBundle>/Game/ or <AppBundle>/ */
    GUEST_VFS_PRIORITY_APP_SUPPORT  = 3,  /* Priority 3: <Application Support>/NFSU2/Game/ */
    GUEST_VFS_PRIORITY_FALLBACK     = 4   /* Fallback read root */
} GuestVFSRootPriority;

#define GUEST_VFS_ROOT_ID_WRITE       UINT8_C(0xFF)

/* VFS Search Root Descriptor */
typedef struct GuestVFSRoot {
    char path[1024];
    uint8_t priority;                       /* Lower number = higher priority */
    uint8_t is_writable;                    /* 1 = writable, 0 = read-only */
    uint8_t active;                         /* 1 = active, 0 = empty slot */
} GuestVFSRoot;

/* In-Memory Case Map Cache Node */
typedef struct GuestVFSNode {
    uint32_t hash;
    char canonical_key[GUEST_VFS_PATH_MAX]; /* Lowercase, forward slashes, e.g. "cars/350z/geometry.bin" */
    char disk_relpath[GUEST_VFS_PATH_MAX];  /* Exact disk casing, e.g. "CARS/350Z/GEOMETRY.BIN" */
    uint8_t root_id;                        /* Index in roots[] or GUEST_VFS_ROOT_ID_WRITE */
    uint8_t priority;                       /* Priority level of the root that supplied this node */
    uint8_t is_dir;                         /* 1 = directory, 0 = regular file */
    struct GuestVFSNode *next;              /* Collision chain */
} GuestVFSNode;

/* In-Memory VFS Resolver with Multi-Root Support */
typedef struct GuestVFS {
    char write_root[1024];                  /* Dedicated writable root (Save/profile data) */
    GuestVFSRoot roots[GUEST_VFS_MAX_SEARCH_ROOTS]; /* Multi-root search hierarchy */
    size_t root_count;
    char read_root[1024];                   /* Backward-compatible legacy read root */
    GuestVFSNode *buckets[GUEST_VFS_HASH_BUCKETS];
    GuestVFSNode *node_pool;
    size_t node_count;
    size_t node_capacity;
    pthread_mutex_t lock;
    int initialized;
} GuestVFS;

/* File Handle Entry with Concurrency & Refcounting */
typedef struct GuestFileSlot {
    int fd;
    int in_use;
    int is_empty;                           /* Simulated EOF for NOMOVIES=2 */
    int closing;                            /* Handle marked for close pending refcount drop */
    uint32_t refcount;                      /* Active concurrent operations referencing this slot */
    uint32_t access;                        /* GENERIC_READ / GENERIC_WRITE */
    uint32_t disposition;
    pthread_mutex_t slot_lock;              /* Mutex protecting non-overlapped read/write/seek */
    char rel_path[GUEST_VFS_PATH_MAX];
} GuestFileSlot;

/* Win32 File Subsystem Table */
typedef struct GuestFileTable {
    GuestVFS vfs;
    GuestFileSlot slots[GUEST_FILE_HANDLE_MAX];
    uint32_t active_handles;
    pthread_mutex_t lock;
    int initialized;
} GuestFileTable;

/* Lifecycle and Configuration */
int guest_file_init(GuestFileTable *table, const char *read_root, const char *write_root);
int guest_file_set_roots(GuestFileTable *table, const char *read_root, const char *write_root);
int guest_file_add_root(GuestFileTable *table, const char *path, uint8_t priority, int is_writable);
int guest_file_setup_ios_roots(GuestFileTable *table,
                               const char *documents_dir,
                               const char *bundle_dir,
                               const char *app_support_dir);
int guest_file_index_roots(GuestFileTable *table);
int guest_file_cleanup(GuestFileTable *table);

/* VFS Path Resolver */
int guest_vfs_resolve(GuestVFS *vfs, const char *win_path, int for_write,
                      char *out_host_path, size_t out_host_sz,
                      char *out_canonical_rel, size_t out_rel_sz);

/* Win32 Guest Import Hook conforming to GuestImportHandler contract */
int guest_file_import(CPU *cpu, const GuestImport *imp, void *context, uint32_t *fault);

#ifdef __cplusplus
}
#endif

#endif /* NFSU2_GUEST_FILE_H */
