#include "win32_runtime_clock.h"

#include <pthread.h>
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

enum {
    CLOCK_WORKER_COUNT = 4,
    CLOCK_ASCENDING_SAMPLES = 4096,
    CLOCK_DESCENDING_SAMPLES = 4096,
    CLOCK_SHUFFLED_SAMPLES = 4096
};

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    unsigned finished;
    int released;
} ClockStartGate;

typedef struct {
    Win32RuntimeClock *clock;
    ClockStartGate *gate;
    unsigned worker_index;
    uint64_t first_timestamp;
    uint64_t maximum_timestamp;
    int results_nondecreasing;
} ClockWorker;

static uint64_t sample_and_check_monotonic(ClockWorker *worker,
                                           uint64_t timestamp,
                                           uint64_t *previous)
{
    if (timestamp > worker->maximum_timestamp)
        worker->maximum_timestamp = timestamp;
    const uint64_t result = win32_runtime_clock_sample_at(worker->clock,
                                                           timestamp);
    if (result < *previous) worker->results_nondecreasing = 0;
    *previous = result;
    return result;
}

static void *clock_worker_main(void *argument)
{
    ClockWorker *worker = (ClockWorker *)argument;
    ClockStartGate *gate = worker->gate;

    pthread_mutex_lock(&gate->mutex);
    ++gate->ready;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->released)
        pthread_cond_wait(&gate->condition, &gate->mutex);
    pthread_mutex_unlock(&gate->mutex);

    worker->maximum_timestamp = worker->first_timestamp;
    uint64_t previous = win32_runtime_clock_sample_at(worker->clock,
                                                       worker->first_timestamp);
    worker->results_nondecreasing = 1;

    for (unsigned i = 0; i < CLOCK_ASCENDING_SAMPLES; ++i) {
        (void)sample_and_check_monotonic(worker,
            UINT64_C(5000000000000) + UINT64_C(1000) + i, &previous);
        if ((i & 255u) == 0u)
            (void)sample_and_check_monotonic(worker, 0, &previous);
    }

    for (unsigned i = 0; i < CLOCK_DESCENDING_SAMPLES; ++i) {
        (void)sample_and_check_monotonic(worker,
            UINT64_C(5000000000000) + UINT64_C(20000) - i, &previous);
        if ((i & 255u) == 0u)
            (void)sample_and_check_monotonic(worker, 0, &previous);
    }

    for (unsigned i = 0; i < CLOCK_SHUFFLED_SAMPLES; ++i) {
        const uint64_t offset = UINT64_C(25000) +
            (uint64_t)((i * 7919u + worker->worker_index * 104729u) % 30000u);
        (void)sample_and_check_monotonic(worker,
            UINT64_C(5000000000000) + offset, &previous);
        if ((i & 255u) == 0u)
            (void)sample_and_check_monotonic(worker, 0, &previous);
    }

    pthread_mutex_lock(&gate->mutex);
    ++gate->finished;
    pthread_cond_broadcast(&gate->condition);
    pthread_mutex_unlock(&gate->mutex);
    return NULL;
}

static int test_concurrent_origin_and_out_of_order_samples(void)
{
    const uint64_t base = UINT64_C(5000000000000);
    const uint64_t first_timestamps[CLOCK_WORKER_COUNT] = {
        base + 100u, base + 200u, base + 300u, base + 400u
    };
    const uint64_t final_timestamp = base + UINT64_C(1000000);
    Win32RuntimeClock clock = {0};
    ClockStartGate gate = {0};
    ClockWorker workers[CLOCK_WORKER_COUNT] = {0};
    pthread_t threads[CLOCK_WORKER_COUNT];
    unsigned created = 0;
    unsigned joined = 0;
    int result = 1;

    if (pthread_mutex_init(&gate.mutex, NULL) != 0) {
        fputs("FAIL: pthread_mutex_init for clock start gate\n", stderr);
        return 1;
    }
    if (pthread_cond_init(&gate.condition, NULL) != 0) {
        fputs("FAIL: pthread_cond_init for clock start gate\n", stderr);
        pthread_mutex_destroy(&gate.mutex);
        return 1;
    }

    for (unsigned i = 0; i < CLOCK_WORKER_COUNT; ++i) {
        workers[i].clock = &clock;
        workers[i].gate = &gate;
        workers[i].worker_index = i;
        workers[i].first_timestamp = first_timestamps[i];
        if (pthread_create(&threads[i], NULL, clock_worker_main, &workers[i]) != 0) {
            fprintf(stderr, "FAIL: pthread_create for clock worker %u\n", i);
            goto cleanup;
        }
        ++created;
    }

    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < CLOCK_WORKER_COUNT)
        pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.released = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);

    for (; joined < created; ++joined) {
        if (pthread_join(threads[joined], NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_join for clock worker %u\n", joined);
            goto cleanup;
        }
    }
    created = 0;

    for (unsigned i = 0; i < CLOCK_WORKER_COUNT; ++i) {
        if (!workers[i].results_nondecreasing) {
            fprintf(stderr, "FAIL: clock worker %u observed a decreasing result\n", i);
            goto cleanup;
        }
    }

    {
        const uint64_t origin = atomic_load(&clock.origin_us);
        uint64_t maximum_timestamp = 0;
        int origin_is_valid = 0;
        for (unsigned i = 0; i < CLOCK_WORKER_COUNT; ++i) {
            if (origin == first_timestamps[i]) origin_is_valid = 1;
            if (workers[i].maximum_timestamp > maximum_timestamp)
                maximum_timestamp = workers[i].maximum_timestamp;
        }
        if (!origin_is_valid) {
            fputs("FAIL: concurrent clock origin was not a worker's first timestamp\n",
                  stderr);
            goto cleanup;
        }

        if (atomic_load(&clock.last_us) != maximum_timestamp - origin) {
            fputs("FAIL: concurrent clock high-water mark did not match submitted samples\n",
                  stderr);
            goto cleanup;
        }

        /* Every stress timestamp is below this sentinel, so the final floor
         * must equal its exact elapsed value regardless of the origin winner. */
        if (win32_runtime_clock_sample_at(&clock, final_timestamp) !=
                final_timestamp - origin ||
            atomic_load(&clock.last_us) != final_timestamp - origin) {
            fputs("FAIL: concurrent clock final floor did not match the known-high sample\n",
                  stderr);
            goto cleanup;
        }
    }
    result = 0;
    goto cleanup;

cleanup:
    if (created != 0) {
        /* Keep the stack-owned gate/context alive until every created worker
         * has left the wait and finished, including a partial-create failure. */
        pthread_mutex_lock(&gate.mutex);
        gate.released = 1;
        pthread_cond_broadcast(&gate.condition);
        while (gate.finished < created)
            pthread_cond_wait(&gate.condition, &gate.mutex);
        pthread_mutex_unlock(&gate.mutex);
        for (unsigned i = joined; i < created; ++i)
            pthread_join(threads[i], NULL);
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    return result;
}

static int test_qpc_and_tsc_interval_agreement(void)
{
    Win32RuntimeClock clock = {0};
    const uint64_t origin = UINT64_C(10000000000);
    CHECK(win32_runtime_clock_sample_at(&clock, origin) == 0);
    const uint64_t qpc_start = win32_runtime_clock_sample_at(&clock, origin + 100000u);
    const uint64_t tsc_start = win32_runtime_tsc_from_us(qpc_start);
    for (unsigned poll = 0; poll < 10000u; ++poll)
        CHECK(win32_runtime_tsc_from_us(qpc_start) == tsc_start);
    const uint64_t qpc_end = win32_runtime_clock_sample_at(&clock, origin + 300000u);
    const uint64_t tsc_end = win32_runtime_tsc_from_us(qpc_end);
    CHECK(qpc_end - qpc_start == UINT64_C(200000));
    CHECK(tsc_end - tsc_start == UINT64_C(600000000));
    CHECK((tsc_end - tsc_start) * WIN32_RUNTIME_CLOCK_FREQUENCY /
          (qpc_end - qpc_start) == WIN32_RUNTIME_TSC_FREQUENCY);
    CHECK(win32_runtime_tsc_from_us(UINT64_MAX) == UINT64_MAX - UINT64_C(2999));
    return 0;
}

int main(void)
{
    CHECK(test_zero_and_unchanged_samples() == 0);
    CHECK(test_elapsed_deadline_after_no_present() == 0);
    CHECK(test_periodic_timer_rearm_without_present() == 0);
    CHECK(test_out_of_order_samples_never_rewind() == 0);
    CHECK(test_large_epoch_and_long_elapsed_rate() == 0);
    CHECK(test_concurrent_origin_and_out_of_order_samples() == 0);
    CHECK(test_qpc_and_tsc_interval_agreement() == 0);
    puts("PASS Win32 runtime monotonic clock | elapsed time, deadlines, timer rearm, concurrent origin and out-of-order samples");
    return 0;
}
