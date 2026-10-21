#include "guest_windows.h"
#include "guest_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

enum {
    STACK_ADDR = 0x00010003u,
    STACK_PAGE = 0x00010000u,
    TEB_ADDR = 0x00030000u,
    LAST_ERROR_OFFSET = 0x34u,
    LAST_ERROR_VALUE = 1400u,
    INITIAL_LAST_ERROR = 0x13579bdfu,
    RETURN_ADDRESS = 0x00401234u,
    FRAME_UNMAPPED = 0x00070000u,
    FRAME_CROSS = 0x00053ff8u,
    PAGE_SIZE = GUEST_MEMORY_GRANULE
};

#define FRAME_TOP (UINT32_MAX - UINT32_C(7))
#define RECT_UNMAPPED UINT32_C(0xdead0000)

static int write_bytes(uint32_t address, const void *bytes, size_t size) {
    void *destination = guest_memory_pointer(address, size, 1);
    if (!destination) return 1;
    memcpy(destination, bytes, size);
    return 0;
}

static int read_bytes(uint32_t address, void *bytes, size_t size) {
    const void *source = guest_memory_pointer(address, size, 0);
    if (!source) return 1;
    memcpy(bytes, source, size);
    return 0;
}

static int write_u32(uint32_t address, uint32_t value) {
    return write_bytes(address, &value, sizeof(value));
}

static int read_u32(uint32_t address, uint32_t *value) {
    return read_bytes(address, value, sizeof(*value));
}

static int write_frame(uint32_t address, uint32_t ret, uint32_t hwnd,
                       uint32_t rect) {
    const uint32_t frame[3] = { ret, hwnd, rect };
    return write_bytes(address, frame, sizeof(frame));
}

static void init_cpu(CPU *cpu, uint32_t esp, uint32_t fs_base) {
    memset(cpu, 0x73, sizeof(*cpu));
    cpu->eax = 0x10293847u;
    cpu->ecx = 0x22334455u;
    cpu->edx = 0x66778899u;
    cpu->ebx = 0xabcdef01u;
    cpu->esp = esp;
    cpu->ebp = 0x55667788u;
    cpu->esi = 0x11223344u;
    cpu->edi = 0x89abcdefu;
    cpu->eip = 0x12344321u;
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x99887766u;
    eflags_set(cpu, 0x0ed7u);
}

static GuestImport get_window_rect_import(const char *library,
                                          const char *name) {
    GuestImport import = { 0xf0004321u, library, name };
    return import;
}

static int expect_completed_cpu(const CPU *actual, const CPU *before,
                                uint32_t ret) {
    CPU expected = *before;
    expected.eax = 0; /* GetWindowRect(NULL, ...) returns FALSE. */
    expected.eip = ret;
    expected.esp = before->esp + 12u;
    if (memcmp(actual, &expected, sizeof(expected)) == 0) return 0;
    fprintf(stderr,
            "FAIL %s:%d: completed call changed CPU beyond EAX/EIP/ESP "
            "(EAX=%08x EIP=%08x ESP=%08x)\n",
            __FILE__, __LINE__, actual->eax, actual->eip, actual->esp);
    return 1;
}

static int expect_unchanged_cpu(const CPU *actual, const CPU *before) {
    if (memcmp(actual, before, sizeof(*actual)) == 0) return 0;
    fprintf(stderr, "FAIL %s:%d: unsupported or faulted call changed CPU\n",
            __FILE__, __LINE__);
    return 1;
}

static int run_null_window(uint32_t frame, uint32_t fs_base, uint32_t rect,
                           uint32_t error_address, int alias_frame) {
    CPU cpu, before;
    uint8_t frame_before[12], frame_after[12];
    uint32_t fault = 0xcafebabeu, last_error = 0;
    GuestImport import = get_window_rect_import("uSeR32.dLl", "GetWindowRect");

    CHECK(write_frame(frame, RETURN_ADDRESS, 0, rect) == 0);
    CHECK(read_bytes(frame, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, frame, fs_base);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32(error_address, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_VALUE);

    CHECK(read_bytes(frame, frame_after, sizeof(frame_after)) == 0);
    if (alias_frame) {
        uint32_t error = LAST_ERROR_VALUE;
        memcpy(frame_before + sizeof(uint32_t), &error, sizeof(error));
    }
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    return 0;
}

static int test_null_window_and_ignored_rect(void) {
    const uint32_t normal_error = TEB_ADDR + LAST_ERROR_OFFSET;
    uint8_t rect_guard[32];

    CHECK(guest_memory_commit(TEB_ADDR, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x00040000u, PAGE_SIZE) == 0);

    /* The RECT pointer is never read or written, even when it is null or unmapped. */
    CHECK(write_u32(normal_error, INITIAL_LAST_ERROR) == 0);
    CHECK(run_null_window(STACK_ADDR, TEB_ADDR, 0, normal_error, 0) == 0);

    CHECK(write_u32(normal_error, INITIAL_LAST_ERROR) == 0);
    CHECK(run_null_window(STACK_ADDR, TEB_ADDR, RECT_UNMAPPED,
                          normal_error, 0) == 0);

    /* Even a readable and writable RECT retains every byte of its guard. */
    memset(rect_guard, 0xA6, sizeof(rect_guard));
    CHECK(write_bytes(0x00040000u, rect_guard, sizeof(rect_guard)) == 0);
    CHECK(write_u32(normal_error, INITIAL_LAST_ERROR) == 0);
    CHECK(run_null_window(STACK_ADDR, TEB_ADDR, 0x00040004u,
                          normal_error, 0) == 0);
    {
        uint8_t after[sizeof(rect_guard)];
        CHECK(read_bytes(0x00040000u, after, sizeof(after)) == 0);
        CHECK(memcmp(rect_guard, after, sizeof(rect_guard)) == 0);
    }

    /* A read-only RECT pointer is ignored just like an unmapped one. */
    CHECK(guest_memory_protect(0x00040000u, PAGE_SIZE,
                               GUEST_MEMORY_READ) == 0);
    CHECK(write_u32(normal_error, INITIAL_LAST_ERROR) == 0);
    CHECK(run_null_window(STACK_ADDR, TEB_ADDR, 0x00040004u,
                          normal_error, 0) == 0);
    CHECK(guest_memory_commit(0x00040000u, PAGE_SIZE) == 0);
    return 0;
}

static int test_teb_faults_are_atomic(void) {
    const uint32_t readonly_error = 0x00060020u;
    const uint32_t cross_error = 0x00093ffeu;
    const uint32_t invalid_fs = 0xdead0000u;
    const uint32_t invalid_error = invalid_fs + LAST_ERROR_OFFSET;
    const uint32_t overflow_fs = UINT32_MAX - 0x10u;
    CPU cpu, before;
    uint8_t frame_before[12], frame_after[12], edge_before[2], edge_after[2];
    uint32_t fault = 0xfeedfaceu;
    GuestImport import = get_window_rect_import("USER32.dll", "GetWindowRect");

    CHECK(guest_memory_commit(readonly_error & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x00090000u, PAGE_SIZE) == 0);
    CHECK(write_u32(readonly_error, INITIAL_LAST_ERROR) == 0);
    CHECK(guest_memory_protect(readonly_error, sizeof(uint32_t),
                               GUEST_MEMORY_READ) == 0);

    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, RECT_UNMAPPED) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, STACK_ADDR, readonly_error - LAST_ERROR_OFFSET);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == readonly_error);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    {
        uint32_t value = 0;
        CHECK(read_u32(readonly_error, &value) == 0);
        CHECK(value == INITIAL_LAST_ERROR);
    }
    CHECK(guest_memory_commit(readonly_error & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);

    /* A DWORD crossing into an uncommitted granule fails before its first bytes. */
    edge_before[0] = 0x4a;
    edge_before[1] = 0xb5;
    CHECK(write_bytes(cross_error, edge_before, sizeof(edge_before)) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, 0) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, STACK_ADDR, cross_error - LAST_ERROR_OFFSET);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == cross_error);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    CHECK(read_bytes(cross_error, edge_after, sizeof(edge_after)) == 0);
    CHECK(memcmp(edge_before, edge_after, sizeof(edge_before)) == 0);

    /* Invalid TEB address and overflowing offset are reported without mutation. */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, RECT_UNMAPPED) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, STACK_ADDR, invalid_fs);
    before = cpu;
    fault = 0xfeedfaceu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == invalid_error);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);

    init_cpu(&cpu, STACK_ADDR, overflow_fs);
    before = cpu;
    fault = 0xfeedfaceu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == UINT32_MAX);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);

    init_cpu(&cpu, STACK_ADDR, 0);
    before = cpu;
    fault = 0xfeedfaceu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -2);
    CHECK(fault == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    return 0;
}

static int test_teb_frame_alias_and_top_boundary(void) {
    const uint32_t alias_error = STACK_ADDR + 4u;
    const uint32_t alias_fs = alias_error - LAST_ERROR_OFFSET;
    const uint32_t top_error = UINT32_MAX - 3u;
    const uint32_t top_fs = top_error - LAST_ERROR_OFFSET;
    const uint32_t wrap_error = UINT32_MAX - 2u;
    const uint32_t wrap_fs = wrap_error - LAST_ERROR_OFFSET;
    CPU cpu, before;
    uint8_t frame_before[12], frame_after[12];
    uint32_t fault = 0xabcdef12u, value = 0;
    GuestImport import = get_window_rect_import("USER32.dll", "GetWindowRect");

    /* TEB LastError overlaps the incoming HWND. Snapshot it before writing 1400. */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, RECT_UNMAPPED) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, STACK_ADDR, alias_fs);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32(alias_error, &value) == 0 && value == LAST_ERROR_VALUE);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    memcpy(frame_before + 4u, &value, sizeof(value));
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);

    /* A four-byte TEB write ending exactly at 4 GiB is valid. */
    CHECK(guest_memory_commit(0xffffc000u, PAGE_SIZE) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, 0) == 0);
    init_cpu(&cpu, STACK_ADDR, top_fs);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32(top_error, &value) == 0 && value == LAST_ERROR_VALUE);

    /* A representable DWORD base that would wrap on a four-byte write faults
     * at that base, before any byte is changed. */
    CHECK(write_bytes(wrap_error, "\x5a\x6b\x7c", 3) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, RECT_UNMAPPED) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    init_cpu(&cpu, STACK_ADDR, wrap_fs);
    before = cpu;
    fault = 0xabcdef12u;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == wrap_error);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    {
        uint8_t bytes[3];
        CHECK(read_bytes(wrap_error, bytes, sizeof(bytes)) == 0);
        CHECK(memcmp(bytes, "\x5a\x6b\x7c", sizeof(bytes)) == 0);
    }
    return 0;
}

static int test_frame_faults(void) {
    CPU cpu, before;
    uint32_t fault = 0xfeedfaceu;
    uint8_t prefix_before[8], prefix_after[8];
    GuestImport import = get_window_rect_import("USER32.dll", "GetWindowRect");

    CHECK(guest_memory_commit(0x00050000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0xffffc000u, PAGE_SIZE) == 0);

    init_cpu(&cpu, FRAME_UNMAPPED, 0xdead0000u);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == FRAME_UNMAPPED);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    CHECK(write_u32(FRAME_CROSS, RETURN_ADDRESS) == 0);
    CHECK(write_u32(FRAME_CROSS + 4u, 0) == 0);
    CHECK(read_bytes(FRAME_CROSS, prefix_before, sizeof(prefix_before)) == 0);
    init_cpu(&cpu, FRAME_CROSS, 0xdead0000u);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == FRAME_CROSS);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(FRAME_CROSS, prefix_after, sizeof(prefix_after)) == 0);
    CHECK(memcmp(prefix_before, prefix_after, sizeof(prefix_before)) == 0);

    CHECK(write_u32(FRAME_TOP, RETURN_ADDRESS) == 0);
    CHECK(write_u32(FRAME_TOP + 4u, 0) == 0);
    CHECK(read_bytes(FRAME_TOP, prefix_before, sizeof(prefix_before)) == 0);
    init_cpu(&cpu, FRAME_TOP, 0xdead0000u);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == FRAME_TOP);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_bytes(FRAME_TOP, prefix_after, sizeof(prefix_after)) == 0);
    CHECK(memcmp(prefix_before, prefix_after, sizeof(prefix_before)) == 0);
    return 0;
}

static int test_nonnull_window_and_unknown_imports(void) {
    CPU cpu, before;
    uint8_t frame_before[12], frame_after[12];
    uint32_t fault = 0xabcdef12u;
    GuestImport import = get_window_rect_import("USER32.dll", "GetWindowRect");
    GuestImport wrong_library = get_window_rect_import("KERNEL32.dll",
                                                       "GetWindowRect");
    GuestImport wrong_name = get_window_rect_import("USER32.dll",
                                                    "GetWindowRectA");
    GuestImport wrong_case = get_window_rect_import("USER32.dll",
                                                    "getWindowRect");

    for (uint32_t hwnd = 1; hwnd <= 2; ++hwnd) {
        CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, hwnd, RECT_UNMAPPED) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
        init_cpu(&cpu, STACK_ADDR, 0); /* Must not probe or write a TEB. */
        before = cpu;
        CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 0);
        CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
        CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
        CHECK(fault == 0xabcdef12u);
    }

    init_cpu(&cpu, FRAME_UNMAPPED, 0);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &wrong_library, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, &wrong_name, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, &wrong_case, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, NULL, NULL, &fault) == 0);
    CHECK(guest_windows_import(NULL, &import, NULL, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(fault == 0xabcdef12u);
    return 0;
}

static int test_null_client_rect(void) {
    CPU cpu, before;
    uint32_t fault = 0x12345678u, last_error = 0;
    GuestImport import = get_window_rect_import("USER32.dll", "GetClientRect");

    CHECK(guest_memory_commit(TEB_ADDR, PAGE_SIZE) == 0);
    CHECK(write_u32(TEB_ADDR + LAST_ERROR_OFFSET, INITIAL_LAST_ERROR) == 0);

    /* NULL HWND with unmapped rect */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 0, RECT_UNMAPPED) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32(TEB_ADDR + LAST_ERROR_OFFSET, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_VALUE);

    /* Non-null HWND must remain unsupported */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, 1, RECT_UNMAPPED) == 0);
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    CHECK(guest_memory_protect(TEB_ADDR, PAGE_SIZE, GUEST_MEMORY_NONE) == 0);
    return 0;
}

static int write_metrics_frame(uint32_t address, uint32_t ret, uint32_t metric) {
    const uint32_t frame[2] = { ret, metric };
    return write_bytes(address, frame, sizeof(frame));
}

static int expect_completed_metrics_cpu(const CPU *actual, const CPU *before,
                                        uint32_t ret, uint32_t expected_eax) {
    CPU expected = *before;
    expected.eax = expected_eax;
    expected.eip = ret;
    expected.esp = before->esp + 8u;
    if (memcmp(actual, &expected, sizeof(expected)) == 0) return 0;
    fprintf(stderr,
            "FAIL %s:%d: completed metrics call changed CPU beyond EAX/EIP/ESP "
            "(EAX=%08x EIP=%08x ESP=%08x)\n",
            __FILE__, __LINE__, actual->eax, actual->eip, actual->esp);
    return 1;
}

static int test_get_system_metrics(void) {
    CPU cpu, before;
    uint32_t fault = 0x12345678u;
    GuestImport import = get_window_rect_import("USER32.dll", "GetSystemMetrics");
    GuestImport wrong_lib = get_window_rect_import("KERNEL32.dll", "GetSystemMetrics");
    GuestImport wrong_name = get_window_rect_import("USER32.dll", "GetSystemMetricsW");

    /* SM_SWAPBUTTON (23): returns 0 (FALSE = normal mouse buttons, left is primary) */
    CHECK(write_metrics_frame(STACK_ADDR, RETURN_ADDRESS, 23) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_metrics_cpu(&cpu, &before, RETURN_ADDRESS, 0) == 0);

    /* Direct handler test */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_user32_get_system_metrics(&cpu, &import, &fault) == 1);
    CHECK(expect_completed_metrics_cpu(&cpu, &before, RETURN_ADDRESS, 0) == 0);

    /* SM_CXSCREEN (0): returns 640 */
    CHECK(write_metrics_frame(STACK_ADDR, RETURN_ADDRESS, 0) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_metrics_cpu(&cpu, &before, RETURN_ADDRESS, 640) == 0);

    /* SM_CYSCREEN (1): returns 480 */
    CHECK(write_metrics_frame(STACK_ADDR, RETURN_ADDRESS, 1) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_metrics_cpu(&cpu, &before, RETURN_ADDRESS, 480) == 0);

    /* Unknown metric (999): returns 0 */
    CHECK(write_metrics_frame(STACK_ADDR, RETURN_ADDRESS, 999) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_metrics_cpu(&cpu, &before, RETURN_ADDRESS, 0) == 0);

    /* Memory fault on unmapped stack frame */
    init_cpu(&cpu, FRAME_UNMAPPED, TEB_ADDR);
    before = cpu;
    fault = 0xabcdef12u;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == FRAME_UNMAPPED);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    /* Wrong library must remain unhandled */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xabcdef12u;
    CHECK(guest_windows_import(&cpu, &wrong_lib, NULL, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(fault == 0xabcdef12u);

    /* Wrong export name must remain unhandled */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xabcdef12u;
    CHECK(guest_windows_import(&cpu, &wrong_name, NULL, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(fault == 0xabcdef12u);

    /* NULL guards */
    CHECK(guest_user32_get_system_metrics(NULL, &import, &fault) == 0);
    CHECK(guest_user32_get_system_metrics(&cpu, NULL, &fault) == 0);
    CHECK(guest_user32_get_system_metrics(&cpu, &import, NULL) == 0);

    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_PAGE, PAGE_SIZE) == 0);

    CHECK(test_null_window_and_ignored_rect() == 0);
    CHECK(test_null_client_rect() == 0);
    CHECK(test_get_system_metrics() == 0);
    CHECK(test_teb_faults_are_atomic() == 0);
    CHECK(test_teb_frame_alias_and_top_boundary() == 0);
    CHECK(test_frame_faults() == 0);
    CHECK(test_nonnull_window_and_unknown_imports() == 0);
    CHECK(guest_memory_shutdown() == 0);
    puts("PASS null window rectangle query");
    return 0;
}
