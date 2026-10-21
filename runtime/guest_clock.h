#ifndef NFSU2_GUEST_CLOCK_H
#define NFSU2_GUEST_CLOCK_H

#include "guest_execution.h"

#include <stdint.h>

enum GuestClockMode {
    GUEST_CLOCK_LIVE = 0,
    GUEST_CLOCK_FIXTURE = 1
};

enum GuestClockOpcode {
    GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY = 1,
    GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER = 2,
    GUEST_CLOCK_GET_TICK_COUNT = 3
};

typedef struct GuestClock {
    uint32_t mode;
    uint64_t frequency, next, increment, query_count, sample_count, trace_hash;
} GuestClock;

/* Initializes a deterministic fixture transactionally. The frequency and
 * increment must be positive signed-64-bit values; initial may be zero but
 * must not exceed INT64_MAX. */
int guest_clock_fixture_init(GuestClock *clock, uint64_t frequency,
                             uint64_t initial, uint64_t increment);

/* Quiesced cleanup. A zeroed object selects the default live clock. */
void guest_clock_cleanup(GuestClock *clock);

/* Supports only the three declared KERNEL32 clock imports. Returns 1 on
 * completion, 0 when unsupported, -1 on guest memory fault, and -2 when the
 * live clock or fixture state cannot be used. */
int guest_clock_import(CPU *cpu, const GuestImport *import, GuestClock *clock,
                       uint32_t *fault);

#endif
