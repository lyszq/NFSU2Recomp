#define _POSIX_C_SOURCE 200809L

#include "guest_clock.h"
#include "guest_memory.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#define GUEST_CLOCK_LIVE_FREQUENCY UINT64_C(1000000000)
#define GUEST_CLOCK_FNV_OFFSET UINT64_C(14695981039346656037)
#define GUEST_CLOCK_FNV_PRIME UINT64_C(1099511628211)

typedef struct GuestClockOperation {
    enum GuestClockOpcode opcode;
    uint32_t frame_size;
    int has_output;
} GuestClockOperation;

static uint32_t read_le32(const void *source)
{
    const uint8_t *bytes = (const uint8_t *)source;
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void write_le64(void *destination, uint64_t value)
{
    uint8_t bytes[8];
    for (unsigned i = 0; i < sizeof bytes; ++i)
        bytes[i] = (uint8_t)(value >> (i * 8u));
    memcpy(destination, bytes, sizeof bytes);
}

static uint64_t fnv_word(uint64_t hash, uint64_t word)
{
    hash ^= word;
    hash *= GUEST_CLOCK_FNV_PRIME;
    return hash;
}

static unsigned char ascii_lower(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') return (unsigned char)(value + ('a' - 'A'));
    return value;
}

static int ascii_equal_case_insensitive(const char *left, const char *right)
{
    if (!left || !right) return 0;
    while (*left && *right) {
        if (ascii_lower((unsigned char)*left) != ascii_lower((unsigned char)*right))
            return 0;
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static int identify_operation(const GuestImport *import, GuestClockOperation *operation)
{
    if (!import || !import->library || !import->name || !operation ||
        !ascii_equal_case_insensitive(import->library, "KERNEL32.dll")) return 0;

    if (strcmp(import->name, "QueryPerformanceFrequency") == 0) {
        operation->opcode = GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY;
        operation->frame_size = 8u;
        operation->has_output = 1;
    } else if (strcmp(import->name, "QueryPerformanceCounter") == 0) {
        operation->opcode = GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER;
        operation->frame_size = 8u;
        operation->has_output = 1;
    } else if (strcmp(import->name, "GetTickCount") == 0) {
        operation->opcode = GUEST_CLOCK_GET_TICK_COUNT;
        operation->frame_size = 4u;
        operation->has_output = 0;
    } else {
        return 0;
    }
    return 1;
}

static int valid_clock_state(const GuestClock *clock)
{
    if (!clock || clock->sample_count > clock->query_count) return 0;

    if (clock->mode == (uint32_t)GUEST_CLOCK_LIVE) {
        if ((clock->frequency != 0u &&
             clock->frequency != GUEST_CLOCK_LIVE_FREQUENCY) ||
            clock->next != 0u || clock->increment != 0u ||
            (!clock->frequency && (clock->query_count || clock->sample_count)))
            return 0;
        return 1;
    }

    if (clock->mode != (uint32_t)GUEST_CLOCK_FIXTURE ||
        !clock->frequency || clock->frequency > (uint64_t)INT64_MAX ||
        clock->next > (uint64_t)INT64_MAX ||
        !clock->increment || clock->increment > (uint64_t)INT64_MAX)
        return 0;
    return 1;
}

static int live_counter(uint64_t *counter)
{
    struct timespec now;
    if (!counter || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L)
        return -1;

    const uint64_t seconds = (uint64_t)now.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)now.tv_nsec) /
                  GUEST_CLOCK_LIVE_FREQUENCY)
        return -1;
    const uint64_t value = seconds * GUEST_CLOCK_LIVE_FREQUENCY +
                           (uint64_t)now.tv_nsec;
    if (value > (uint64_t)INT64_MAX) return -1;
    *counter = value;
    return 0;
}

static uint32_t to_milliseconds(uint64_t counter, uint64_t frequency)
{
    /* The product can exceed 64 bits for valid counters and small
     * frequencies. A 128-bit intermediate keeps floor(counter*1000/freq)
     * exact before the Win32 DWORD wraps modulo 2^32. */
    __uint128_t value = (__uint128_t)counter * 1000u;
    value /= frequency;
    return (uint32_t)value;
}

int guest_clock_fixture_init(GuestClock *clock, uint64_t frequency,
                             uint64_t initial, uint64_t increment)
{
    if (!clock || !frequency || frequency > (uint64_t)INT64_MAX ||
        initial > (uint64_t)INT64_MAX || !increment ||
        increment > (uint64_t)INT64_MAX)
        return EINVAL;

    const GuestClock fixture = {
        .mode = GUEST_CLOCK_FIXTURE,
        .frequency = frequency,
        .next = initial,
        .increment = increment,
        .query_count = 0,
        .sample_count = 0,
        .trace_hash = GUEST_CLOCK_FNV_OFFSET
    };
    *clock = fixture;
    return 0;
}

void guest_clock_cleanup(GuestClock *clock)
{
    if (clock) memset(clock, 0, sizeof(*clock));
}

int guest_clock_import(CPU *cpu, const GuestImport *import, GuestClock *clock,
                       uint32_t *fault)
{
    GuestClockOperation operation;
    if (!identify_operation(import, &operation)) return 0;
    if (!cpu || !fault) return 0;
    if (!clock) {
        *fault = 0u;
        return -2;
    }

    const uint8_t *frame_bytes = (const uint8_t *)guest_memory_pointer(
        cpu->esp, operation.frame_size, 0);
    if (!frame_bytes) {
        *fault = cpu->esp;
        return -1;
    }

    uint8_t frame[8] = {0};
    memcpy(frame, frame_bytes, operation.frame_size);
    const uint32_t return_ip = read_le32(frame);
    uint32_t output_address = 0u;
    uint8_t *output = NULL;
    if (operation.has_output) {
        output_address = read_le32(frame + 4u);
        if (!output_address ||
            (uint64_t)output_address + sizeof(uint64_t) > GUEST_MEMORY_SIZE) {
            *fault = output_address;
            return -1;
        }
        output = (uint8_t *)guest_memory_pointer(output_address,
                                                 sizeof(uint64_t), 1);
        if (!output) {
            *fault = output_address;
            return -1;
        }
    }

    if (!valid_clock_state(clock)) {
        *fault = 0u;
        return -2;
    }
    if (clock->query_count == UINT64_MAX ||
        (operation.opcode != GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY &&
         clock->sample_count == UINT64_MAX)) {
        *fault = 0u;
        return -2;
    }

    const int is_sample = operation.opcode != GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY;
    if (is_sample && clock->mode == (uint32_t)GUEST_CLOCK_FIXTURE &&
        clock->next > (uint64_t)INT64_MAX - clock->increment) {
        *fault = 0u;
        return -2;
    }

    uint64_t sampled_counter = 0u;
    if (is_sample) {
        if (clock->mode == (uint32_t)GUEST_CLOCK_FIXTURE) {
            sampled_counter = clock->next;
        } else if (live_counter(&sampled_counter) != 0) {
            *fault = 0u;
            return -2;
        }
    }

    uint64_t returned_value;
    if (operation.opcode == GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY) {
        returned_value = clock->mode == (uint32_t)GUEST_CLOCK_FIXTURE
            ? clock->frequency : GUEST_CLOCK_LIVE_FREQUENCY;
    } else if (operation.opcode == GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER) {
        returned_value = sampled_counter;
    } else {
        const uint64_t frequency = clock->mode == (uint32_t)GUEST_CLOCK_FIXTURE
            ? clock->frequency : GUEST_CLOCK_LIVE_FREQUENCY;
        returned_value = to_milliseconds(sampled_counter, frequency);
    }

    GuestClock updated = *clock;
    if (updated.query_count == 0u) updated.trace_hash = GUEST_CLOCK_FNV_OFFSET;
    updated.query_count++;
    if (is_sample) updated.sample_count++;
    updated.trace_hash = fnv_word(updated.trace_hash, operation.opcode);
    updated.trace_hash = fnv_word(updated.trace_hash, returned_value);
    if (updated.mode == (uint32_t)GUEST_CLOCK_LIVE)
        updated.frequency = GUEST_CLOCK_LIVE_FREQUENCY;
    else if (is_sample)
        updated.next += updated.increment;

    /* All reads and validation are complete. The only guest-memory write is
     * now infallible, and the stack snapshot permits output/frame aliasing. */
    if (output) write_le64(output, returned_value);
    *clock = updated;
    cpu->eax = operation.opcode == GUEST_CLOCK_GET_TICK_COUNT
        ? (uint32_t)returned_value : 1u;
    cpu->eip = return_ip;
    cpu->esp += operation.frame_size;
    return 1;
}
