#include "win32_runtime_clock.h"

#include <stdio.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int test_zero_and_unchanged_samples(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t start = UINT64_C(1792672133655000);

    CHECK(win32_runtime_clock_sample_at(&clock, 0) == 0);
    CHECK(atomic_load(&clock.origin_us) == 0);
    CHECK(atomic_load(&clock.last_us) == 0);

    CHECK(win32_runtime_clock_sample_at(&clock, start) == 0);
    CHECK(atomic_load(&clock.origin_us) == start);
    for (unsigned poll = 0; poll < 100000u; ++poll)
        CHECK(win32_runtime_clock_sample_at(&clock, start) == 0);
    CHECK(atomic_load(&clock.last_us) == 0);
    CHECK(win32_runtime_clock_sample_at(&clock, start + 1u) == 1u);
    return 0;
}

static int test_elapsed_deadline_after_no_present(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t start = UINT64_C(8000000000000);
    const uint64_t timer_period_us = UINT64_C(200000);

    CHECK(win32_runtime_clock_sample_at(&clock, start) == 0);
    const uint64_t previous_sample =
        win32_runtime_clock_sample_at(&clock, start + UINT64_C(100000));
    CHECK(previous_sample == UINT64_C(100000));

    /* A deadline 200 ms after the previous sample still expires with no frame. */
    const uint64_t deadline = previous_sample + timer_period_us;
    const uint64_t after_idle =
        win32_runtime_clock_sample_at(&clock, start + UINT64_C(300001));
    CHECK(after_idle == UINT64_C(300001));
    CHECK(after_idle >= deadline);
    return 0;
}

static int test_periodic_timer_rearm_without_present(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t start = UINT64_C(4200000000000);
    const uint64_t period_a = UINT64_C(5000);
    const uint64_t period_b = UINT64_C(7000);
    const uint64_t duration = UINT64_C(2100000);
    uint64_t due_a = period_a;
    uint64_t due_b = period_b;
    unsigned fired_a = 0;
    unsigned fired_b = 0;

    for (uint64_t offset = 0; offset <= duration; offset += 1000u) {
        const uint64_t elapsed =
            win32_runtime_clock_sample_at(&clock, start + offset);
        if (elapsed >= due_a) {
            ++fired_a;
            due_a = elapsed + period_a;
        }
        if (elapsed >= due_b) {
            ++fired_b;
            due_b = elapsed + period_b;
        }
    }

    CHECK(fired_a == 420u);
    CHECK(fired_b == 300u);
    CHECK(atomic_load(&clock.last_us) == duration);
    return 0;
}

static int test_out_of_order_samples_never_rewind(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t start = UINT64_C(9000000000000000);

    CHECK(win32_runtime_clock_sample_at(&clock, start) == 0);
    CHECK(win32_runtime_clock_sample_at(&clock, start + 1000u) == 1000u);
    CHECK(win32_runtime_clock_sample_at(&clock, start + 800u) == 1000u);
    CHECK(win32_runtime_clock_sample_at(&clock, start + 999u) == 1000u);
    CHECK(win32_runtime_clock_sample_at(&clock, 0) == 1000u);
    CHECK(atomic_load(&clock.origin_us) == start);
    CHECK(atomic_load(&clock.last_us) == 1000u);
    CHECK(win32_runtime_clock_sample_at(&clock, start + 1200u) == 1200u);
    return 0;
}

static int test_large_epoch_and_long_elapsed_rate(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t start = UINT64_C(15000000000000000);

    CHECK(win32_runtime_clock_sample_at(&clock, start) == 0);
    CHECK(win32_runtime_clock_sample_at(&clock,
                                        start + UINT64_C(2345678)) ==
          UINT64_C(2345678));
    CHECK(win32_runtime_clock_sample_at(&clock,
                                        start + UINT64_C(60000000)) ==
          UINT64_C(60000000));
    CHECK(atomic_load(&clock.last_us) == UINT64_C(60000000));
    CHECK(WIN32_RUNTIME_CLOCK_FREQUENCY == UINT64_C(1000000));
    return 0;
}

int main(void)
{
    CHECK(test_zero_and_unchanged_samples() == 0);
    CHECK(test_elapsed_deadline_after_no_present() == 0);
    CHECK(test_periodic_timer_rearm_without_present() == 0);
    CHECK(test_out_of_order_samples_never_rewind() == 0);
    CHECK(test_large_epoch_and_long_elapsed_rate() == 0);
    puts("PASS Win32 runtime monotonic clock | elapsed time, deadlines, timer rearm, out-of-order samples");
    return 0;
}
