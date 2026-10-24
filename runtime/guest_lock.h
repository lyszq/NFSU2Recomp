#ifndef NFS_GUEST_LOCK_H
#define NFS_GUEST_LOCK_H

#include <stdint.h>

/* Host waits must not hold the process-wide guest execution mutex. A token
 * records ownership so render/UI callers outside guest execution are no-ops.
 * Drop every backend mutex before restoring the guest lock, then reacquire
 * backend locks and recheck their conditions. */
int guest_host_wait_begin(void);
void guest_host_wait_end(int released);
/* Safe COM boundary: call only after Present's stdcall epilogue, with no
 * backend mutex or temporary COM argument/replay context held. */
void guest_frame_checkpoint(void);

typedef struct {
    uint64_t host_waits;
    uint64_t host_wait_ns;
    uint64_t max_host_wait_ns;
    uint64_t acquisition_wait_ns;
    uint64_t acquisition_wait_max_ns;
    uint64_t acquisitions;
    uint64_t queued_waiters;
    uint64_t fair_handoffs;
} GuestLockSnapshot;

void guest_lock_snapshot(GuestLockSnapshot *snapshot);

#endif
