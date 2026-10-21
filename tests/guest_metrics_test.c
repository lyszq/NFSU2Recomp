/* Native contract tests for the bounded GetSystemMetrics guest import. */

#include "guest_memory.h"
#include "guest_windows.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    STACK_BASE = 0x00400000u,
    TEB_BASE = 0x00C00000u,
    STACK_ADDR = STACK_BASE + 0x100u,
    PAGE_SIZE = GUEST_MEMORY_GRANULE,
    RETURN_IP = 0x00123456u,
    IMPORT_IP = 0xF0000023u,
    SM_SWAPBUTTON = 23u,
    LAST_ERROR_OFFSET = 0x34u
};

static int write_bytes(uint32_t address, const void *source, size_t size) {
    void *destination = guest_memory_pointer(address, size, 1);
    if (!destination) return 1;
    memcpy(destination, source, size);
    return 0;
}

static int read_bytes(uint32_t address, void *destination, size_t size) {
    const void *source = guest_memory_pointer(address, size, 0);
    if (!source) return 1;
    memcpy(destination, source, size);
    return 0;
}

static void write_frame(uint32_t esp, uint32_t return_ip, uint32_t metric) {
    const uint32_t frame[2] = { return_ip, metric };
    assert(write_bytes(esp, frame, sizeof(frame)) == 0);
}

static void init_cpu(CPU *cpu, uint32_t esp) {
    memset(cpu, 0x5A, sizeof(*cpu));
    cpu->eax = 0xAABBCCDDu;
    cpu->ecx = 0x11112222u;
    cpu->edx = 0x33334444u;
    cpu->ebx = 0x55556666u;
    cpu->esp = esp;
    cpu->ebp = 0x77778888u;
    cpu->esi = 0x9999AAAAu;
    cpu->edi = 0xBBBBCCCCu;
    cpu->eip = IMPORT_IP;
    cpu->fs_base = TEB_BASE;
    cpu->gs_base = 0xDDDDEEEEu;
    cpu->cf = 1;
    cpu->pf = 0;
    cpu->af = 1;
    cpu->zf = 0;
    cpu->sf = 1;
    cpu->of = 0;
    cpu->df = 1;
}

static GuestImport swap_import(void) {
    const GuestImport import = {
        .iat = 0x1000u,
        .library = "USER32.dll",
        .name = "GetSystemMetrics"
    };
    return import;
}

static void test_primary_left_metric_is_read_only_stdcall(void) {
    const uint32_t last_error_address = TEB_BASE + LAST_ERROR_OFFSET;
    const uint32_t last_error_sentinel = 0x76543210u;
    assert(guest_memory_commit(STACK_BASE, PAGE_SIZE) == 0);
    assert(guest_memory_commit(TEB_BASE, PAGE_SIZE) == 0);
    assert(write_bytes(last_error_address, &last_error_sentinel,
                       sizeof(last_error_sentinel)) == 0);
    write_frame(STACK_ADDR, RETURN_IP, SM_SWAPBUTTON);

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR);
    CPU expected = cpu;
    expected.eax = 0;
    expected.eip = RETURN_IP;
    expected.esp += 8u;

    uint8_t stack_before[PAGE_SIZE];
    uint32_t error_before = 0;
    assert(read_bytes(STACK_BASE, stack_before, sizeof(stack_before)) == 0);
    assert(read_bytes(last_error_address, &error_before, sizeof(error_before)) == 0);
    assert(error_before == last_error_sentinel);

    GuestImport import = swap_import();
    uint32_t fault = 0xDEADBEEFu;
    assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == 1);
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(fault == 0xDEADBEEFu);

    uint8_t stack_after[PAGE_SIZE];
    uint32_t error_after = 0;
    assert(read_bytes(STACK_BASE, stack_after, sizeof(stack_after)) == 0);
    assert(read_bytes(last_error_address, &error_after, sizeof(error_after)) == 0);
    assert(memcmp(stack_before, stack_after, sizeof(stack_before)) == 0);
    assert(error_after == last_error_sentinel);
    puts("PASS: test_primary_left_metric_is_read_only_stdcall");
}

static void test_readonly_frame_aliased_with_teb_last_error(void) {
    write_frame(STACK_ADDR, RETURN_IP, SM_SWAPBUTTON);
    assert(guest_memory_protect(STACK_BASE, PAGE_SIZE, GUEST_MEMORY_READ) == 0);

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR);
    cpu.fs_base = STACK_ADDR - LAST_ERROR_OFFSET;
    CPU expected = cpu;
    expected.eax = 0;
    expected.eip = RETURN_IP;
    expected.esp += 8u;
    uint32_t frame_before[2] = { 0, 0 };
    assert(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);

    GuestImport import = swap_import();
    uint32_t fault = 0xDEADBEEFu;
    assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == 1);
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    uint32_t frame_after[2] = { 0, 0 };
    assert(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    assert(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    assert(fault == 0xDEADBEEFu);

    assert(guest_memory_protect(STACK_BASE, PAGE_SIZE,
                                GUEST_MEMORY_READ_WRITE) == 0);
    puts("PASS: test_readonly_frame_aliased_with_teb_last_error");
}

static void test_unknown_metrics_are_strictly_unsupported(void) {
    const uint32_t metrics[] = { 0u, 1u, UINT32_MAX };
    GuestImport import = swap_import();
    for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); ++i) {
        write_frame(STACK_ADDR, RETURN_IP, metrics[i]);
        CPU cpu;
        init_cpu(&cpu, STACK_ADDR);
        CPU before = cpu;
        uint32_t frame_before[2] = { 0, 0 };
        assert(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
        uint32_t fault = 0xDEADBEEFu;

        assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == 0);
        assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
        uint32_t frame_after[2] = { 0, 0 };
        assert(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
        assert(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
        assert(fault == 0xDEADBEEFu);
    }
    puts("PASS: test_unknown_metrics_are_strictly_unsupported");
}

static void test_wrong_library_or_export_is_unsupported(void) {
    GuestImport import = swap_import();
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR);
    CPU before = cpu;
    uint32_t fault = 0xDEADBEEFu;

    import.library = "KERNEL32.dll";
    assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == 0);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(fault == 0xDEADBEEFu);

    import = swap_import();
    import.name = "GetSystemMetricsA";
    assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == 0);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(fault == 0xDEADBEEFu);
    puts("PASS: test_wrong_library_or_export_is_unsupported");
}

static void test_unmapped_partial_readonly_and_overflow_frames_fault(void) {
    GuestImport import = swap_import();
    const uint32_t bad_frames[] = {
        0x00800000u,
        STACK_BASE + PAGE_SIZE - 4u,
        0xFFFFFFFCu
    };
    for (size_t i = 0; i < sizeof(bad_frames) / sizeof(bad_frames[0]); ++i) {
        CPU cpu;
        init_cpu(&cpu, bad_frames[i]);
        CPU before = cpu;
        uint32_t fault = 0xDEADBEEFu;
        assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == -1);
        assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
        assert(fault == bad_frames[i]);
    }

    /* Read permission is sufficient; write-only access is not a readable frame. */
    write_frame(STACK_ADDR, RETURN_IP, SM_SWAPBUTTON);
    assert(guest_memory_protect(STACK_BASE, PAGE_SIZE, GUEST_MEMORY_NONE) == 0);
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR);
    CPU before = cpu;
    uint32_t fault = 0xDEADBEEFu;
    assert(guest_user32_get_system_metrics(&cpu, &import, &fault) == -1);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(fault == STACK_ADDR);
    assert(guest_memory_protect(STACK_BASE, PAGE_SIZE,
                                GUEST_MEMORY_READ_WRITE) == 0);
    puts("PASS: test_unmapped_partial_readonly_and_overflow_frames_fault");
}

int main(void) {
    assert(guest_memory_init() == 0);
    test_primary_left_metric_is_read_only_stdcall();
    test_readonly_frame_aliased_with_teb_last_error();
    test_unknown_metrics_are_strictly_unsupported();
    test_wrong_library_or_export_is_unsupported();
    test_unmapped_partial_readonly_and_overflow_frames_fault();
    assert(guest_memory_shutdown() == 0);
    puts("All guest_metrics tests passed");
    return 0;
}
