#ifndef NFSU2_GAME_SESSION_H
#define NFSU2_GAME_SESSION_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    NFS_GAME_SESSION_IDLE = 0,
    NFS_GAME_SESSION_PREPARING = 1,
    NFS_GAME_SESSION_RUNNING = 2,
    NFS_GAME_SESSION_PAUSE_REQUESTED = 3,
    NFS_GAME_SESSION_EXITED = 4,
    NFS_GAME_SESSION_FAILED = 5
};

/* Starts one process-lifetime guest session from the authenticated app copy.
 * asset_root must be the directory containing executable_path.  Save files
 * are redirected to save_root.  Guest memory is intentionally never torn
 * down while any guest, audio, or renderer worker may still be live.
 */
int nfs_game_session_start(const char *executable_path,
                           const char *asset_root,
                           const char *save_root,
                           char *diagnostic,
                           size_t diagnostic_capacity);

/* Lifecycle state. Inactive requests a cooperative guest pause at runtime
 * checkpoints and clears all input. Activating broadcasts the resume signal.
 */
void nfs_game_session_set_active(int active);
void nfs_game_session_checkpoint(void);
int nfs_game_session_get_state(void);
void nfs_game_session_get_status(char *diagnostic, size_t diagnostic_capacity);

#ifdef __cplusplus
}
#endif

#endif
