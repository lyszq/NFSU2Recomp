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
#define GUEST_FILE_HANDLE_MAX         256
#define GUEST_VFS_PATH_MAX            260
#define GUEST_VFS_HASH_BUCKETS        4096

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

/* Win32 Handle & Return Constants */
#define GUEST_INVALID_HANDLE_VALUE    UINT32_C(0xFFFFFFFF)
#define GUEST_INVALID_SET_FILE_POINTER UINT32_C(0xFFFFFFFF)
#define GUEST_INVALID_FILE_SIZE       UINT32_C(0xFFFFFFFF)

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

/* VFS Root Identifiers */
typedef enum GuestVFSRootId {
    GUEST_VFS_ROOT_READ = 0,   /* Read-only asset root (Game directory) */
    GUEST_VFS_ROOT_WRITE = 1   /* Read-write user root (Save/memcard directory) */
} GuestVFSRootId;

/* In-Memory Case Map Cache Node */
typedef struct GuestVFSNode {
    uint32_t hash;
    char canonical_key[GUEST_VFS_PATH_MAX]; /* Lowercase, forward slashes, e.g. "cars/350z/geometry.bin" */
    char disk_relpath[GUEST_VFS_PATH_MAX];  /* Exact disk casing, e.g. "CARS/350Z/GEOMETRY.BIN" */
    uint8_t root_id;                        /* GUEST_VFS_ROOT_READ or GUEST_VFS_ROOT_WRITE */
    uint8_t is_dir;                         /* 1 = directory, 0 = regular file */
    struct GuestVFSNode *next;              /* Collision chain */
} GuestVFSNode;

/* In-Memory VFS Resolver */
typedef struct GuestVFS {
    char read_root[1024];
    char write_root[1024];
    GuestVFSNode *buckets[GUEST_VFS_HASH_BUCKETS];
    GuestVFSNode *node_pool;
    size_t node_count;
    size_t node_capacity;
    pthread_mutex_t lock;
    int initialized;
} GuestVFS;

/* File Handle Entry */
typedef struct GuestFileSlot {
    int fd;
    int in_use;
    int is_empty;                           /* Simulated EOF for NOMOVIES=2 */
    uint32_t access;                        /* GENERIC_READ / GENERIC_WRITE */
    uint32_t disposition;
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
