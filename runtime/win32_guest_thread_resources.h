#ifndef NFSU2_WIN32_GUEST_THREAD_RESOURCES_H
#define NFSU2_WIN32_GUEST_THREAD_RESOURCES_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* Dedicated guest ranges for the single legacy Win32 thread runtime.
 * The TEB pool sits after this target's mapped image (rounded end 0x00930000)
 * and before the legacy heap at 0x10000000. The stack pool starts after the
 * COM buffer allocator's maximum 1 MiB commit padding beyond 0x60000000 and
 * ends exactly where the primary guest stack begins. Do not merge this with
 * the separately bounded GuestProcess/GuestHeap allocators.
 */
#define WIN32_GUEST_THREAD_TEB_BASE       UINT32_C(0x01000000)
#define WIN32_GUEST_THREAD_TEB_SIZE       UINT32_C(0x00002000)
#define WIN32_GUEST_THREAD_STACK_BASE     UINT32_C(0x60100000)
#define WIN32_GUEST_THREAD_STACK_SIZE     UINT32_C(0x00100000)
#define WIN32_GUEST_THREAD_STACK_LIMIT    UINT32_C(0x7f000000)
#define WIN32_GUEST_THREAD_SLOT_COUNT     495u

#define WIN32_GUEST_THREAD_TEB_LIMIT \
    (WIN32_GUEST_THREAD_TEB_BASE + \
     WIN32_GUEST_THREAD_TEB_SIZE * WIN32_GUEST_THREAD_SLOT_COUNT)

typedef struct Win32GuestThreadResourcePool {
    uint8_t used[WIN32_GUEST_THREAD_SLOT_COUNT];
} Win32GuestThreadResourcePool;

typedef struct Win32GuestThreadReservation {
    uint32_t teb;
    uint32_t stack_low;
    uint32_t stack_high;
    uint16_t slot;
    uint8_t active;
} Win32GuestThreadReservation;

/* Callers serialize these operations (the legacy runtime uses g_lock). */
static inline void *win32_guest_thread_claim_resume(void **pending,
                                                    int *started) {
    if (!pending || !started || *started || !*pending) return 0;
    void *claimed = *pending;
    *pending = 0;
    *started = 1;
    return claimed;
}

static inline void *win32_guest_thread_claim_close(void **pending,
                                                   int *started) {
    if (!pending || !started || *started || !*pending) return 0;
    void *claimed = *pending;
    *pending = 0;
    return claimed;
}

static inline void win32_guest_thread_resources_init(
    Win32GuestThreadResourcePool *pool) {
    if (pool) memset(pool, 0, sizeof *pool);
}

static inline int win32_guest_thread_resources_reserve(
    Win32GuestThreadResourcePool *pool,
    Win32GuestThreadReservation *reservation) {
    if (!pool || !reservation) return EINVAL;
    for (uint32_t slot = 0; slot < WIN32_GUEST_THREAD_SLOT_COUNT; ++slot) {
        if (pool->used[slot]) continue;
        const uint64_t teb = (uint64_t)WIN32_GUEST_THREAD_TEB_BASE +
                             (uint64_t)slot * WIN32_GUEST_THREAD_TEB_SIZE;
        const uint64_t stack = (uint64_t)WIN32_GUEST_THREAD_STACK_BASE +
                               (uint64_t)slot * WIN32_GUEST_THREAD_STACK_SIZE;
        if (teb + WIN32_GUEST_THREAD_TEB_SIZE > WIN32_GUEST_THREAD_TEB_LIMIT ||
            stack + WIN32_GUEST_THREAD_STACK_SIZE >
                WIN32_GUEST_THREAD_STACK_LIMIT)
            return ENOSPC;
        pool->used[slot] = 1;
        *reservation = (Win32GuestThreadReservation){
            (uint32_t)teb,
            (uint32_t)stack,
            (uint32_t)(stack + WIN32_GUEST_THREAD_STACK_SIZE),
            (uint16_t)slot,
            1
        };
        return 0;
    }
    return ENOSPC;
}

/* Release only when the caller owns a reservation that is not active on a
 * guest CPU. Production calls this after worker completion and guest_unlock;
 * failed never-started workers can use the more specific wrapper below. */
static inline int win32_guest_thread_resources_release_quiesced(
    Win32GuestThreadResourcePool *pool,
    Win32GuestThreadReservation *reservation) {
    if (!pool || !reservation || !reservation->active ||
        reservation->slot >= WIN32_GUEST_THREAD_SLOT_COUNT)
        return EINVAL;
    const uint32_t slot = reservation->slot;
    const uint32_t expected_teb = WIN32_GUEST_THREAD_TEB_BASE +
                                  slot * WIN32_GUEST_THREAD_TEB_SIZE;
    const uint32_t expected_stack = WIN32_GUEST_THREAD_STACK_BASE +
                                    slot * WIN32_GUEST_THREAD_STACK_SIZE;
    if (!pool->used[slot] || reservation->teb != expected_teb ||
        reservation->stack_low != expected_stack ||
        reservation->stack_high != expected_stack +
                                      WIN32_GUEST_THREAD_STACK_SIZE)
        return EINVAL;
    pool->used[slot] = 0;
    reservation->active = 0;
    return 0;
}

static inline int win32_guest_thread_resources_release_failed_start(
    Win32GuestThreadResourcePool *pool,
    Win32GuestThreadReservation *reservation) {
    return win32_guest_thread_resources_release_quiesced(pool, reservation);
}

#endif
