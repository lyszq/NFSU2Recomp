#define _POSIX_C_SOURCE 200809L

#include "guest_clock.h"
#include "guest_memory.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

enum {
    STACK_PAGE = 0x00010000u,
    STACK_ADDR = 0x00010003u,
    OUTPUT_PAGE = 0x00020000u,
    TEB_PAGE = 0x00030000u,
    UNMAPPED_PAGE = 0x00040000u,
    TOP_PAGE = 0xffffc000u,
    RETURN_ADDRESS = 0x00401234u,
    LAST_ERROR_OFFSET = 0x34u,
    LAST_ERROR_SENTINEL = 0xdecafbadU
};

#define FNV_OFFSET UINT64_C(14695981039346656037)
#define FNV_PRIME UINT64_C(1099511628211)
#define TEST_STACK (STACK_ADDR + 0x20u)
#define OUTPUT_A (OUTPUT_PAGE + 0x123u)
#define OUTPUT_B (OUTPUT_PAGE + 0x1f9u)

static void put_le32(void *destination, uint32_t value)
{
    uint8_t *bytes = (uint8_t *)destination;
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t get_le32(const void *source)
{
    const uint8_t *bytes = (const uint8_t *)source;
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t get_le64(const void *source)
{
    const uint8_t *bytes = (const uint8_t *)source;
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (i * 8u);
    return value;
}

static int write_guest(uint32_t address, const void *source, size_t size)
{
    void *destination = guest_memory_pointer(address, size, 1);
    if (!destination) return 1;
    memcpy(destination, source, size);
    return 0;
}

static int read_guest(uint32_t address, void *destination, size_t size)
{
    const void *source = guest_memory_pointer(address, size, 0);
    if (!source) return 1;
    memcpy(destination, source, size);
    return 0;
}

static int write_frame(uint32_t esp, uint32_t return_ip, uint32_t output,
                       uint32_t frame_size)
{
    uint8_t frame[8] = {0};
    put_le32(frame, return_ip);
    if (frame_size == 8u) put_le32(frame + 4u, output);
    return write_guest(esp, frame, frame_size);
}

static GuestImport api(const char *library, const char *name)
{
    GuestImport import = { 0xf0001234u, library, name };
    return import;
}

static void init_cpu(CPU *cpu, uint32_t esp)
{
    memset(cpu, 0x5a, sizeof(*cpu));
    cpu->eax = 0x10293847u;
    cpu->ecx = 0x22334455u;
    cpu->edx = 0x66778899u;
    cpu->ebx = 0xabcdef01u;
    cpu->esp = esp;
    cpu->ebp = 0x55667788u;
    cpu->esi = 0x11223344u;
    cpu->edi = 0x89abcdefu;
    cpu->eip = 0x12344321u;
    cpu->fs_base = TEB_PAGE;
    cpu->gs_base = 0x99887766u;
    cpu->cf = 1u;
    cpu->pf = 0u;
    cpu->af = 1u;
    cpu->zf = 0u;
    cpu->sf = 1u;
    cpu->of = 0u;
    cpu->df = 1u;
    cpu->id_flag = 1u;
    cpu->top = 5;
    cpu->fcw = 0x027fu;
    cpu->fsw = 0x4321u;
    cpu->st[0] = 3.25;
    cpu->st[7] = -19.5;
    cpu->mm[3] = UINT64_C(0x0123456789abcdef);
    cpu->xmm[4].u64[0] = UINT64_C(0xfedcba9876543210);
    cpu->xmm[4].u64[1] = UINT64_C(0x1122334455667788);
}

static int expect_completed_cpu(const CPU *actual, const CPU *before,
                                uint32_t eax, uint32_t frame_size)
{
    CPU expected = *before;
    expected.eax = eax;
    expected.eip = RETURN_ADDRESS;
    expected.esp += frame_size;
    if (!memcmp(actual, &expected, sizeof(expected))) return 0;
    fprintf(stderr,
            "FAIL %s:%d: completed clock import changed non-result CPU state\n",
            __FILE__, __LINE__);
    return 1;
}

static uint64_t hash_word(uint64_t hash, uint64_t word)
{
    return (hash ^ word) * FNV_PRIME;
}

static uint64_t hash_event(uint64_t hash, uint32_t opcode, uint64_t value)
{
    return hash_word(hash_word(hash, opcode), value);
}

static uint32_t expected_tick(uint64_t counter, uint64_t frequency)
{
    return (uint32_t)(((__uint128_t)counter * 1000u) / frequency);
}

static int call_output(GuestClock *clock, CPU *cpu, const char *name,
                       uint32_t output, uint32_t *fault)
{
    if (write_frame(cpu->esp, RETURN_ADDRESS, output, 8u) != 0) {
        fprintf(stderr, "FAIL %s:%d: could not prepare clock output frame\n",
                __FILE__, __LINE__);
        return -99;
    }
    GuestImport import = api("kErNeL32.DlL", name);
    return guest_clock_import(cpu, &import, clock, fault);
}

static int call_tick(GuestClock *clock, CPU *cpu, uint32_t *fault)
{
    if (write_frame(cpu->esp, RETURN_ADDRESS, 0u, 4u) != 0) {
        fprintf(stderr, "FAIL %s:%d: could not prepare tick frame\n",
                __FILE__, __LINE__);
        return -99;
    }
    GuestImport import = api("KERNEL32.dll", "GetTickCount");
    return guest_clock_import(cpu, &import, clock, fault);
}

static int test_fixture_sequence_and_reset(void)
{
    GuestClock clock = {0};
    CPU cpu, before;
    uint32_t fault = 0xfeedfaceu;
    const uint64_t frequency = UINT64_C(1000000);
    const uint64_t initial = UINT64_C(1000000);
    const uint64_t increment = UINT64_C(1000);
    uint8_t last_error[4];
    put_le32(last_error, LAST_ERROR_SENTINEL);
    CHECK(write_guest(TEB_PAGE + LAST_ERROR_OFFSET, last_error, sizeof last_error) == 0);

    CHECK(guest_clock_fixture_init(&clock, frequency, initial, increment) == 0);
    CHECK(clock.mode == (uint32_t)GUEST_CLOCK_FIXTURE && clock.frequency == frequency &&
          clock.next == initial && clock.increment == increment &&
          clock.query_count == 0u && clock.sample_count == 0u &&
          clock.trace_hash == FNV_OFFSET);

    init_cpu(&cpu, TEST_STACK);
    before = cpu;
    CHECK(call_output(&clock, &cpu, "QueryPerformanceFrequency", OUTPUT_A,
                      &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, 1u, 8u) == 0);
    uint8_t bytes[8];
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == frequency);
    CHECK(clock.next == initial && clock.query_count == 1u &&
          clock.sample_count == 0u &&
          clock.trace_hash == hash_event(FNV_OFFSET,
              GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY, frequency));

    init_cpu(&cpu, TEST_STACK);
    before = cpu;
    CHECK(call_output(&clock, &cpu, "QueryPerformanceCounter", OUTPUT_B,
                      &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, 1u, 8u) == 0);
    CHECK(read_guest(OUTPUT_B, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == initial);
    uint64_t hash = hash_event(clock.trace_hash,
                               GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER, initial);
    CHECK(clock.next == initial + increment && clock.query_count == 2u &&
          clock.sample_count == 1u && clock.trace_hash == hash);

    init_cpu(&cpu, TEST_STACK);
    before = cpu;
    CHECK(call_tick(&clock, &cpu, &fault) == 1);
    uint32_t tick = expected_tick(initial + increment, frequency);
    CHECK(expect_completed_cpu(&cpu, &before, tick, 4u) == 0);
    hash = hash_event(hash, GUEST_CLOCK_GET_TICK_COUNT, tick);
    CHECK(clock.next == initial + 2u * increment && clock.query_count == 3u &&
          clock.sample_count == 2u && clock.trace_hash == hash);
    CHECK(read_guest(TEB_PAGE + LAST_ERROR_OFFSET, last_error,
                     sizeof last_error) == 0 &&
          get_le32(last_error) == LAST_ERROR_SENTINEL);

    CHECK(guest_clock_fixture_init(&clock, frequency, initial, increment) == 0);
    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&clock, &cpu, "QueryPerformanceCounter", OUTPUT_A,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == initial && clock.next == initial + increment &&
          clock.query_count == 1u && clock.sample_count == 1u &&
          clock.trace_hash == hash_event(FNV_OFFSET,
              GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER, initial));
    guest_clock_cleanup(&clock);
    const GuestClock zero = {0};
    CHECK(!memcmp(&clock, &zero, sizeof(clock)));
    return 0;
}

static int test_frequency_invariance(void)
{
    GuestClock low = {0}, high = {0};
    CPU cpu;
    uint32_t fault = 0;
    uint8_t bytes[8];
    const uint64_t initial = UINT64_C(2000000);
    const uint64_t increment = UINT64_C(1000);
    CHECK(guest_clock_fixture_init(&low, UINT64_C(1000000), initial,
                                   increment) == 0);
    CHECK(guest_clock_fixture_init(&high, UINT64_C(2000000), initial,
                                   increment) == 0);

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&low, &cpu, "QueryPerformanceFrequency", OUTPUT_A,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == UINT64_C(1000000));
    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&high, &cpu, "QueryPerformanceFrequency", OUTPUT_B,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_B, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == UINT64_C(2000000));

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&low, &cpu, "QueryPerformanceCounter", OUTPUT_A,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == initial);
    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&high, &cpu, "QueryPerformanceCounter", OUTPUT_B,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_B, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == initial);

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_tick(&low, &cpu, &fault) == 1);
    const uint32_t low_tick = cpu.eax;
    init_cpu(&cpu, TEST_STACK);
    CHECK(call_tick(&high, &cpu, &fault) == 1);
    const uint32_t high_tick = cpu.eax;
    CHECK(low_tick == 2001u && high_tick == 1000u && low_tick != high_tick);
    CHECK(low.next == initial + 2u * increment &&
          high.next == initial + 2u * increment);
    return 0;
}

static uint64_t host_monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
}

static int test_live_clock(void)
{
    GuestClock clock = {0};
    CPU cpu;
    uint32_t fault = 0;
    uint8_t bytes[8];
    uint64_t hash = FNV_OFFSET;
    CHECK(clock.mode == (uint32_t)GUEST_CLOCK_LIVE);

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&clock, &cpu, "QueryPerformanceFrequency", OUTPUT_A,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0 &&
          get_le64(bytes) == UINT64_C(1000000000));
    hash = hash_event(hash, GUEST_CLOCK_QUERY_PERFORMANCE_FREQUENCY,
                      UINT64_C(1000000000));

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&clock, &cpu, "QueryPerformanceCounter", OUTPUT_A,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_A, bytes, sizeof bytes) == 0);
    const uint64_t first = get_le64(bytes);
    CHECK(first > 0u && first <= (uint64_t)INT64_MAX);
    hash = hash_event(hash, GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER, first);

    init_cpu(&cpu, TEST_STACK);
    CHECK(call_output(&clock, &cpu, "QueryPerformanceCounter", OUTPUT_B,
                      &fault) == 1);
    CHECK(read_guest(OUTPUT_B, bytes, sizeof bytes) == 0);
    const uint64_t second = get_le64(bytes);
    CHECK(second >= first);
    hash = hash_event(hash, GUEST_CLOCK_QUERY_PERFORMANCE_COUNTER, second);

    const uint64_t before_ns = host_monotonic_ns();
    CHECK(before_ns != 0u);
    init_cpu(&cpu, TEST_STACK);
    cpu.fs_base = 0u; /* No TEB is required or probed by these clock APIs. */
    CPU before = cpu;
    CHECK(call_tick(&clock, &cpu, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, cpu.eax, 4u) == 0);
    const uint64_t after_ns = host_monotonic_ns();
    CHECK(after_ns >= before_ns);
    const uint32_t first_tick = expected_tick(before_ns, UINT64_C(1000000000));
    const uint32_t last_tick = expected_tick(after_ns, UINT64_C(1000000000));
    CHECK((uint32_t)(cpu.eax - first_tick) <=
          (uint32_t)(last_tick - first_tick));
    hash = hash_event(hash, GUEST_CLOCK_GET_TICK_COUNT, cpu.eax);
    CHECK(clock.mode == (uint32_t)GUEST_CLOCK_LIVE &&
          clock.frequency == UINT64_C(1000000000) && clock.next == 0u &&
          clock.increment == 0u && clock.query_count == 4u &&
          clock.sample_count == 3u && clock.trace_hash == hash);
    uint8_t last_error[4];
    CHECK(read_guest(TEB_PAGE + LAST_ERROR_OFFSET, last_error,
                     sizeof last_error) == 0 &&
          get_le32(last_error) == LAST_ERROR_SENTINEL);
    return 0;
}

static int test_aliasing_and_errors(void)
{
    GuestClock clock = {0};
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu;
    uint8_t bytes[8], frame_before[8], frame_after[8];
    CHECK(guest_clock_fixture_init(&clock, 1000u, 77u, 5u) == 0);

    /* Output aliases the entire active frame. The return address and output
     * pointer must already be snapshotted before the successful output write. */
    init_cpu(&cpu, TEST_STACK + 0x40u);
    before = cpu;
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, cpu.esp, 8u) == 0);
    GuestImport qpc = api("KERNEL32.dll", "QueryPerformanceCounter");
    CHECK(guest_clock_import(&cpu, &qpc, &clock, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, 1u, 8u) == 0);
    CHECK(read_guest(before.esp, bytes, sizeof bytes) == 0 && get_le64(bytes) == 77u);

    /* NULL, unmapped, read-only, and wrapping out pointers fail atomically. */
    const uint32_t bad_outputs[] = {
        0u, UNMAPPED_PAGE, OUTPUT_PAGE,
        OUTPUT_PAGE + GUEST_MEMORY_GRANULE - 4u, UINT32_MAX - 3u
    };
    const uint8_t output_guard[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    CHECK(write_guest(OUTPUT_PAGE, output_guard, sizeof output_guard) == 0);
    for (size_t i = 0; i < sizeof bad_outputs / sizeof bad_outputs[0]; ++i) {
        if (bad_outputs[i] == OUTPUT_PAGE)
            CHECK(guest_memory_protect(OUTPUT_PAGE, GUEST_MEMORY_GRANULE,
                                       GUEST_MEMORY_NONE) == 0);
        init_cpu(&cpu, TEST_STACK + 0x80u + (uint32_t)i * 0x10u);
        CHECK(write_frame(cpu.esp, RETURN_ADDRESS, bad_outputs[i], 8u) == 0);
        before = cpu;
        GuestClock snapshot = clock;
        fault = 0xcafebabeu;
        CHECK(guest_clock_import(&cpu, &qpc, &clock, &fault) == -1);
        CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
              !memcmp(&clock, &snapshot, sizeof(clock)));
        CHECK(fault == bad_outputs[i]);
        if (bad_outputs[i] == OUTPUT_PAGE)
            CHECK(guest_memory_protect(OUTPUT_PAGE, GUEST_MEMORY_GRANULE,
                                       GUEST_MEMORY_READ_WRITE) == 0);
    }
    CHECK(read_guest(OUTPUT_PAGE, frame_after, sizeof frame_after) == 0 &&
          !memcmp(output_guard, frame_after, sizeof output_guard));

    /* A readonly frame fails before any fixture or CPU state changes. */
    init_cpu(&cpu, TEST_STACK + 0x100u);
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, OUTPUT_A, 8u) == 0);
    before = cpu;
    GuestClock snapshot = clock;
    CHECK(guest_memory_protect(STACK_PAGE, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_NONE) == 0);
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, &clock, &fault) == -1 &&
          fault == before.esp);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&clock, &snapshot, sizeof(clock)));
    CHECK(guest_memory_protect(STACK_PAGE, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_READ_WRITE) == 0);

    /* A readable frame cannot straddle into an uncommitted stack granule. */
    init_cpu(&cpu, STACK_PAGE + GUEST_MEMORY_GRANULE - 4u);
    before = cpu;
    snapshot = clock;
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, &clock, &fault) == -1 &&
          fault == before.esp);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&clock, &snapshot, sizeof(clock)));

    /* Frame crossing the 4 GiB boundary is rejected without wrap. */
    init_cpu(&cpu, UINT32_MAX - 3u);
    before = cpu;
    snapshot = clock;
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, &clock, &fault) == -1 &&
          fault == before.esp);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&clock, &snapshot, sizeof(clock)));

    /* Unsupported import tags never touch the CPU or clock. */
    init_cpu(&cpu, TEST_STACK + 0x140u);
    before = cpu;
    snapshot = clock;
    GuestImport unknown_library = api("USER32.dll", "GetTickCount");
    GuestImport unknown_name = api("KERNEL32.dll", "gettickcount");
    CHECK(guest_clock_import(&cpu, &unknown_library, &clock, &fault) == 0);
    CHECK(guest_clock_import(&cpu, &unknown_name, &clock, &fault) == 0);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&clock, &snapshot, sizeof(clock)));

    /* Counter exhaustion is an API-state stop, never a partial sample. */
    GuestClock exhausted = {0};
    CHECK(guest_clock_fixture_init(&exhausted, 1000u,
                                   (uint64_t)INT64_MAX - 1u, 2u) == 0);
    init_cpu(&cpu, TEST_STACK + 0x180u);
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, OUTPUT_B, 8u) == 0);
    CHECK(write_guest(OUTPUT_B, (uint8_t[8]){1,2,3,4,5,6,7,8}, 8u) == 0);
    before = cpu;
    snapshot = exhausted;
    memcpy(frame_before, guest_memory_pointer(cpu.esp, 8u, 0), 8u);
    memcpy(bytes, guest_memory_pointer(OUTPUT_B, 8u, 0), 8u);
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, &exhausted, &fault) == -2 && fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&exhausted, &snapshot, sizeof(exhausted)));
    CHECK(read_guest(cpu.esp, frame_after, sizeof(frame_after)) == 0 &&
          !memcmp(frame_before, frame_after, sizeof(frame_before)));
    CHECK(read_guest(OUTPUT_B, frame_after, sizeof(frame_after)) == 0 &&
          !memcmp(bytes, frame_after, sizeof(bytes)));

    /* Invalid fixture setup preserves the caller's existing state. */
    GuestClock invalid, invalid_before;
    memset(&invalid, 0x6b, sizeof invalid);
    invalid_before = invalid;
    CHECK(guest_clock_fixture_init(&invalid, 0u, 1u, 1u) == EINVAL);
    CHECK(!memcmp(&invalid, &invalid_before, sizeof invalid));
    CHECK(guest_clock_fixture_init(&invalid,
          (uint64_t)INT64_MAX + 1u, 1u, 1u) == EINVAL);
    CHECK(!memcmp(&invalid, &invalid_before, sizeof invalid));
    CHECK(guest_clock_fixture_init(&invalid, 1u,
          (uint64_t)INT64_MAX + 1u, 1u) == EINVAL);
    CHECK(!memcmp(&invalid, &invalid_before, sizeof invalid));
    CHECK(guest_clock_fixture_init(&invalid, 1u, 1u, 0u) == EINVAL);
    CHECK(!memcmp(&invalid, &invalid_before, sizeof invalid));
    CHECK(guest_clock_fixture_init(&invalid, 1u, 1u,
          (uint64_t)INT64_MAX + 1u) == EINVAL);
    CHECK(!memcmp(&invalid, &invalid_before, sizeof invalid));

    GuestClock count_exhausted = {0};
    CHECK(guest_clock_fixture_init(&count_exhausted, 1000u, 10u, 1u) == 0);
    count_exhausted.query_count = UINT64_MAX;
    count_exhausted.sample_count = UINT64_MAX;
    init_cpu(&cpu, TEST_STACK + 0x1c0u);
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, OUTPUT_A, 8u) == 0);
    before = cpu;
    snapshot = count_exhausted;
    CHECK(guest_clock_import(&cpu, &qpc, &count_exhausted, &fault) == -2);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&count_exhausted, &snapshot, sizeof(snapshot)));

    GuestClock bad_mode = clock;
    bad_mode.mode = UINT32_MAX;
    init_cpu(&cpu, TEST_STACK + 0x200u);
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, OUTPUT_B, 8u) == 0);
    before = cpu;
    snapshot = bad_mode;
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, &bad_mode, &fault) == -2 && fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)) &&
          !memcmp(&bad_mode, &snapshot, sizeof(snapshot)));

    init_cpu(&cpu, TEST_STACK + 0x240u);
    CHECK(write_frame(cpu.esp, RETURN_ADDRESS, OUTPUT_B, 8u) == 0);
    before = cpu;
    fault = 0xcafebabeu;
    CHECK(guest_clock_import(&cpu, &qpc, NULL, &fault) == -2 && fault == 0u);
    CHECK(!memcmp(&cpu, &before, sizeof(cpu)));
    return 0;
}

int main(void)
{
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_PAGE, GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(OUTPUT_PAGE, GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(TEB_PAGE, GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(TOP_PAGE, GUEST_MEMORY_GRANULE) == 0);
    CHECK(test_fixture_sequence_and_reset() == 0);
    CHECK(test_frequency_invariance() == 0);
    CHECK(test_live_clock() == 0);
    CHECK(test_aliasing_and_errors() == 0);
    CHECK(guest_memory_shutdown() == 0);
    puts("PASS guest clock contracts");
    return 0;
}
