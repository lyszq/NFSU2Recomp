#if !defined(__APPLE__)
#error "metal_framebuffer_pool_test requires Apple's Dispatch framework"
#endif

#include "../runtime/metal_framebuffer_pool.h"
#include <stdio.h>

#define CHECK(condition) do { \
    if (!(condition)){ \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static void release_like_command_buffer_completion(dispatch_semaphore_t semaphore,
                                                    _Atomic int *busy,
                                                    int slot){
    /* Mirrors fb_release's lease bookkeeping; this test has no command buffer/GPU. */
    atomic_store(&busy[slot], 0);
    dispatch_semaphore_signal(semaphore);
}

static int test_three_leases_full_ring_and_retry(void){
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(3);
    _Atomic int busy[3];
    _Atomic unsigned long overlap = 0;
    for (int i = 0; i < 3; i++) atomic_init(&busy[i], 0);

    CHECK(semaphore != NULL);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == 0);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == 1);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == 2);
    CHECK(atomic_load(&busy[0]) == 1);
    CHECK(atomic_load(&busy[1]) == 1);
    CHECK(atomic_load(&busy[2]) == 1);
    CHECK(atomic_load(&overlap) == 2);

    /* A saturated-ring failure leaves owners and credits alone. */
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == -1);
    CHECK(atomic_load(&busy[0]) == 1);
    CHECK(atomic_load(&busy[1]) == 1);
    CHECK(atomic_load(&busy[2]) == 1);
    CHECK(atomic_load(&overlap) == 2);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == -1);
    CHECK(atomic_load(&busy[0]) == 1);
    CHECK(atomic_load(&busy[1]) == 1);
    CHECK(atomic_load(&busy[2]) == 1);

    /* Completion returns a lease; an immediate retry can claim that same slot. */
    release_like_command_buffer_completion(semaphore, busy, 1);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 3, &overlap) == 1);
    CHECK(atomic_load(&busy[0]) == 1);
    CHECK(atomic_load(&busy[1]) == 1);
    CHECK(atomic_load(&busy[2]) == 1);
    CHECK(atomic_load(&overlap) == 3);

    release_like_command_buffer_completion(semaphore, busy, 0);
    release_like_command_buffer_completion(semaphore, busy, 1);
    release_like_command_buffer_completion(semaphore, busy, 2);
    CHECK(atomic_load(&busy[0]) == 0);
    CHECK(atomic_load(&busy[1]) == 0);
    CHECK(atomic_load(&busy[2]) == 0);
    return 1;
}

static int test_inconsistent_owner_restores_credit(void){
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(1);
    _Atomic int busy[1];
    atomic_init(&busy[0], 1); /* Semaphore has credit, but owner table has no free slot. */

    CHECK(semaphore != NULL);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 1, NULL) == -2);
    CHECK(atomic_load(&busy[0]) == 1);

    /* Fixing the owner table lets the next call consume the restored credit. */
    atomic_store(&busy[0], 0);
    CHECK(nfs_metal_fb_try_acquire(semaphore, busy, 1, NULL) == 0);
    release_like_command_buffer_completion(semaphore, busy, 0);
    CHECK(atomic_load(&busy[0]) == 0);
    return 1;
}

int main(void){
    if (!test_three_leases_full_ring_and_retry()) return 1;
    if (!test_inconsistent_owner_restores_credit()) return 1;
    puts("metal framebuffer pool bookkeeping tests passed (no GPU/device coverage)");
    return 0;
}
