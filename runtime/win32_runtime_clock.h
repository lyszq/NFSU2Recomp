#ifndef NFSU2_WIN32_RUNTIME_CLOCK_H
#define NFSU2_WIN32_RUNTIME_CLOCK_H

#include <stdatomic.h>
#include <stdint.h>

/* Runtime QPC values are elapsed microseconds, matching the 1 MHz QPF. */
#define WIN32_RUNTIME_CLOCK_FREQUENCY UINT64_C(1000000)
/* A defined guest TSC rate, independent of the physical Apple CPU frequency.
 * Its interval ratios must agree with QPC even when no frames are presented. */
#define WIN32_RUNTIME_TSC_FREQUENCY UINT64_C(3000000000)

static inline uint64_t win32_runtime_tsc_from_us(uint64_t elapsed_us)
{
    /* Unsigned wrap matches the guest's 64-bit timestamp counter. */
    return elapsed_us * (WIN32_RUNTIME_TSC_FREQUENCY /
                         WIN32_RUNTIME_CLOCK_FREQUENCY);
}

typedef struct {
    _Atomic uint64_t origin_us;
    _Atomic uint64_t last_us;
} Win32RuntimeClock;

/*
 * Convert an absolute monotonic timestamp into process-relative microseconds.
 * The first nonzero timestamp wins the origin race. Samples that arrive late
 * or out of order return the greatest elapsed value observed so far. A zero
 * timestamp represents a source failure: return the current floor without
 * initializing the origin or advancing time.
 *
 * This clock has no frame or polling dependency. Callers may zero-initialize
 * the state and share it across threads.
 */
static inline uint64_t win32_runtime_clock_sample_at(Win32RuntimeClock *clock,
                                                       uint64_t now_us)
{
    if (!clock) return 0;

    if (!now_us)
        return atomic_load_explicit(&clock->last_us, memory_order_acquire);

    uint64_t origin = atomic_load_explicit(&clock->origin_us,
                                           memory_order_acquire);
    if (!origin) {
        uint64_t expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &clock->origin_us, &expected, now_us,
                memory_order_acq_rel, memory_order_acquire)) {
            origin = now_us;
        } else {
            origin = expected;
        }
    }

    const uint64_t elapsed = now_us > origin ? now_us - origin : 0;
    uint64_t last = atomic_load_explicit(&clock->last_us,
                                         memory_order_acquire);
    while (elapsed > last) {
        if (atomic_compare_exchange_weak_explicit(
                &clock->last_us, &last, elapsed,
                memory_order_acq_rel, memory_order_acquire)) {
            return elapsed;
        }
    }
    return last;
}

#endif /* NFSU2_WIN32_RUNTIME_CLOCK_H */
