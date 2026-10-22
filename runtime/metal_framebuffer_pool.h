#ifndef NFS_METAL_FRAMEBUFFER_POOL_H
#define NFS_METAL_FRAMEBUFFER_POOL_H

#include <dispatch/dispatch.h>
#include <stdatomic.h>

/* Return a claimed slot, -1 when no semaphore credit is immediately available,
 * or -2 when the semaphore and owner table disagree (credit is restored). */
static inline int nfs_metal_fb_try_acquire(dispatch_semaphore_t semaphore,
                                           _Atomic int *busy,
                                           int count,
                                           _Atomic unsigned long *overlap){
    if (!semaphore || !busy || count <= 0) return -2;
    if (dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) != 0) return -1;

    int got = -1, any = 0;
    for (int i = 0; i < count; i++){
        if (got < 0){
            int free_slot = 0;
            if (atomic_compare_exchange_strong(&busy[i], &free_slot, 1)){
                got = i;
                continue;
            }
        }
        if (atomic_load(&busy[i])) any = 1;
    }
    if (any && overlap) atomic_fetch_add(overlap, 1ul);
    if (got < 0){
        dispatch_semaphore_signal(semaphore);
        return -2;
    }
    return got;
}

#endif
