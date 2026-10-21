/* Synthetic guest for the authored startup_probe.c.in regression harness.
 * No proprietary image or generated game source is read or linked here. */
#include "guest_bootstrap.h"
#include "guest_execution.h"
#include "guest_heap.h"
#include "guest_memory.h"
#include "guest_process.h"
#include "guest_windows.h"
#include "guest_cursor.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nfs_private_startup_probe(const GuestPEImage *image, char *out, size_t capacity);

#define SYN_IMAGE_BASE 0x0075b000u
#define SYN_IMAGE_SIZE 0x00004000u
#define SYN_ENTRY 0x0075bcc7u
#define SYN_NESTED 0x0075bdc7u
#define SYN_STEP_A 0x0075bcc8u
#define SYN_STEP_B 0x0075bcc9u
#define SYN_STEP_C 0x0075bccau
#define SYN_STEP_ALT 0x0075bd00u
#define SYN_IAT_BASE (SYN_IMAGE_BASE + 0x100u)
#define SYN_HEAP_BLOCK (GUEST_HEAP_BASE + GUEST_MEMORY_GRANULE)
#define SYN_STACK_START (GUEST_STACK_HI - 0x1004u)

enum TestMode {
    MODE_VALID,
    MODE_TRACE,
    MODE_IMAGE,
    MODE_TEB,
    MODE_STACK,
    MODE_HEAP,
    MODE_PROCESS,
    MODE_STEP_COUNT,
    MODE_CALL_COUNT,
    MODE_API_COUNT,
    MODE_BLOCK_COUNT,
    MODE_DEPTH,
    MODE_TARGET,
    MODE_USER_OBJECTS,
    MODE_TOOLHELP
};

static enum TestMode mode;

static int mode_from_arg(const char *name, enum TestMode *out) {
    static const struct { const char *name; enum TestMode mode; } modes[] = {
        {"valid", MODE_VALID}, {"trace", MODE_TRACE}, {"image", MODE_IMAGE},
        {"teb", MODE_TEB}, {"stack", MODE_STACK}, {"heap", MODE_HEAP},
        {"process", MODE_PROCESS}, {"step_count", MODE_STEP_COUNT},
        {"call_count", MODE_CALL_COUNT}, {"api_count", MODE_API_COUNT},
        {"block_count", MODE_BLOCK_COUNT}, {"depth", MODE_DEPTH},
        {"target", MODE_TARGET}, {"user_objects", MODE_USER_OBJECTS}, {"toolhelp", MODE_TOOLHELP}
    };
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; ++i) {
        if (strcmp(name, modes[i].name) == 0) {
            *out = modes[i].mode;
            return 0;
        }
    }
    return EINVAL;
}

static void write32(void *destination, uint32_t value) {
    memcpy(destination, &value, sizeof value);
}

static uint32_t read32(const void *source) {
    uint32_t value;
    memcpy(&value, source, sizeof value);
    return value;
}

static int write_frame(CPU *cpu, uint32_t return_ip, const uint32_t *args,
                       size_t argument_count) {
    size_t size = (argument_count + 1u) * sizeof(uint32_t);
    uint8_t *frame = guest_memory_pointer(cpu->esp, size, 1);
    if (!frame) return EFAULT;
    write32(frame, return_ip);
    for (size_t i = 0; i < argument_count; ++i)
        write32(frame + (i + 1u) * sizeof(uint32_t), args[i]);
    return 0;
}

void sub_0075bdc7(CPU *cpu) {
    (void)cpu;
}

void sub_0075bcc7(CPU *cpu) {
    GuestCursorSnapshot fixture = guest_cursor_get_snapshot();
    if (!guest_cursor_is_synthetic() || fixture.coords.x != 320 ||
        fixture.coords.y != 180 || !(fixture.flags & GUEST_CURSOR_FLAG_AVAILABLE)) abort();
    if (mode == MODE_DEPTH) guest_execution_call(cpu, SYN_NESTED);

    guest_execution_step(cpu, mode == MODE_TRACE ? SYN_STEP_ALT : SYN_STEP_A);
    if (mode == MODE_STEP_COUNT) guest_execution_step(cpu, SYN_STEP_ALT);

    const uint32_t create_args[] = {1u, 0u, GUEST_MEMORY_GRANULE};
    if (write_frame(cpu, SYN_STEP_B, create_args, 3u)) abort();
    guest_execution_call(cpu, GUEST_IMPORT_BASE + 0u);
    guest_execution_step(cpu, SYN_STEP_B);
    uint32_t saved_eax = cpu->eax, saved_edx = cpu->edx;
    guest_execution_rdtsc(cpu);
    cpu->eax = saved_eax;
    cpu->edx = saved_edx;

    uint32_t heap = GUEST_HEAP_BASE;
    if (mode == MODE_BLOCK_COUNT) heap += 0x100000u;
    const uint32_t alloc_args[] = {heap, 8u, 16u};
    if (write_frame(cpu, SYN_STEP_C, alloc_args, 3u)) abort();
    guest_execution_call(cpu, GUEST_IMPORT_BASE + 1u);

    if (mode == MODE_CALL_COUNT || mode == MODE_API_COUNT) {
        if (write_frame(cpu, SYN_STEP_C, NULL, 0u)) abort();
        guest_execution_call(cpu, GUEST_IMPORT_BASE + 4u);
    }
    guest_execution_step(cpu, SYN_STEP_C);
    saved_eax = cpu->eax;
    saved_edx = cpu->edx;
    guest_execution_rdtsc(cpu);
    cpu->eax = saved_eax;
    cpu->edx = saved_edx;

    if (mode == MODE_IMAGE) g_mem[SYN_IMAGE_BASE + 0x20u] ^= 1u;
    if (mode == MODE_TEB) g_mem[GUEST_TEB_BASE + 0x80u] ^= 1u;
    if (mode == MODE_STACK) g_mem[SYN_STACK_START] ^= 1u;
    if (mode == MODE_HEAP) g_mem[SYN_HEAP_BLOCK] ^= 1u;
    if (mode == MODE_PROCESS) g_mem[GUEST_PROCESS_BASE + 0x800u] ^= 1u;

    guest_execution_call(cpu, GUEST_IMPORT_BASE +
                        (mode == MODE_TARGET ? 3u : 2u));
}

const uint32_t nfs_startup_addresses[] = {SYN_ENTRY, SYN_NESTED};
const GuestFunction nfs_startup_functions[] = {sub_0075bcc7, sub_0075bdc7};
const uint32_t nfs_startup_count = 2u;
const GuestImport nfs_startup_imports[] = {
    {SYN_IAT_BASE + 0u, "KERNEL32.dll", "HeapCreate"},
    {SYN_IAT_BASE + 4u, "KERNEL32.dll", "HeapAlloc"},
    {SYN_IAT_BASE + 8u, "KERNEL32.dll", "ProbeStopA"},
    {SYN_IAT_BASE + 12u, "KERNEL32.dll", "ProbeStopB"},
    {SYN_IAT_BASE + 16u, "KERNEL32.dll", "GetACP"}
};
const uint32_t nfs_startup_import_count =
    (uint32_t)(sizeof nfs_startup_imports / sizeof nfs_startup_imports[0]);

/* A narrow synthetic import handler keeps the test fixture deterministic
 * while using the real guest execution, memory, process, and heap modules. */
int guest_windows_import(CPU *cpu, const GuestImport *import, void *context,
                         uint32_t *fault) {
    if (!cpu || !import || !import->name || !context || !fault) return 0;
    GuestWindows *windows = context;
    if (strcmp(import->name, "HeapCreate") == 0) {
        if (mode == MODE_TOOLHELP) windows->toolhelp.snapshots[0].process_id = 101u;
        CPU clock_cpu = *cpu;
        const GuestImport tick = {.library="KERNEL32.dll", .name="GetTickCount"};
        if (guest_clock_import(&clock_cpu, &tick, &windows->clock, fault) != 1) abort();
        /* A typed virtual descriptor fixture; corruption changes no guest bytes,
         * counts or registers, so only the exact object-metadata check catches it. */
        windows->user_objects.count = 1;
        windows->user_objects.entries[0] = (GuestUserObject){
            .handle=0x00b10001u,
            .type=mode == MODE_USER_OBJECTS ? GUEST_USER_OBJECT_ICON : GUEST_USER_OBJECT_CURSOR,
            .source=GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED,
            .module=0, .resource_id=32512u, .shared=1u
        };
        const uint8_t *frame = guest_memory_pointer(cpu->esp, 16u, 0);
        if (!frame) { *fault = cpu->esp; return -1; }
        uint32_t result = 0;
        uint32_t options = read32(frame + 4u);
        uint32_t initial = read32(frame + 8u);
        uint32_t maximum = read32(frame + 12u);
        int rc = guest_heap_create(&windows->heaps, initial, maximum, &result);
        if (rc) return -2;
        cpu->eax = result;
        cpu->eip = read32(frame);
        cpu->esp += 16u;
        (void)options;
        return 1;
    }
    if (strcmp(import->name, "HeapAlloc") == 0) {
        const uint8_t *frame = guest_memory_pointer(cpu->esp, 16u, 0);
        if (!frame) { *fault = cpu->esp; return -1; }
        uint32_t heap = read32(frame + 4u);
        uint32_t flags = read32(frame + 8u);
        uint32_t size = read32(frame + 12u);
        uint32_t result = 0;
        int rc = guest_heap_alloc(&windows->heaps, heap, size, !!(flags & 8u), &result);
        cpu->eax = rc ? 0u : result;
        cpu->eip = read32(frame);
        cpu->esp += 16u;
        return 1;
    }
    if (strcmp(import->name, "GetACP") == 0) {
        const uint8_t *frame = guest_memory_pointer(cpu->esp, 4u, 0);
        if (!frame) { *fault = cpu->esp; return -1; }
        cpu->eax = 1252u;
        cpu->eip = read32(frame);
        cpu->esp += 4u;
        return 1;
    }
    return 0;
}

int guest_windows_cleanup(GuestWindows *windows) {
    if (!windows) return EINVAL;
    guest_process_cleanup(&windows->process);
    windows->unhandled_exception_filter = 0;
    return 0;
}

uint32_t guest_critical_count(const GuestCriticalSet *set) {
    (void)set;
    return 0u;
}

unsigned guest_tls_count(const GuestTLSSet *set) {
    (void)set;
    return 0u;
}

int main(int argc, char **argv) {
    if (argc != 2 || mode_from_arg(argv[1], &mode)) {
        fprintf(stderr, "usage: ios-startup-probe-synthetic MODE\n");
        return 2;
    }
    int rc = guest_memory_init();
    if (rc) {
        fprintf(stderr, "guest_memory_init: %d\n", rc);
        return 2;
    }
    rc = guest_memory_commit(SYN_IMAGE_BASE, SYN_IMAGE_SIZE);
    if (rc) {
        fprintf(stderr, "image commit: %d\n", rc);
        guest_memory_shutdown();
        return 2;
    }
    memset(g_mem + SYN_IMAGE_BASE, 0, SYN_IMAGE_SIZE);
    /* Keep the hash window mapped even in the block-count corruption case. */
    rc = guest_memory_commit(SYN_HEAP_BLOCK, GUEST_MEMORY_GRANULE);
    if (rc) {
        fprintf(stderr, "heap window commit: %d\n", rc);
        guest_memory_shutdown();
        return 2;
    }
    memset(g_mem + SYN_HEAP_BLOCK, 0, GUEST_MEMORY_GRANULE);

    GuestPEImage image = {
        .image_base = SYN_IMAGE_BASE,
        .image_size = SYN_IMAGE_SIZE,
        .entry_point = SYN_ENTRY
    };
    char output[512] = {0};
    guest_cursor_reset();
    guest_cursor_set_host_pos(900.0f, 500.0f, true);
    rc = nfs_private_startup_probe(&image, output, sizeof output);
    GuestCursorSnapshot live = guest_cursor_get_snapshot();
    if (guest_cursor_is_synthetic() || live.coords.x != 900 || live.coords.y != 500 ||
        !(live.flags & GUEST_CURSOR_FLAG_DOWN)) {
        fprintf(stderr, "startup fixture leaked or mutated live cursor\n");
        return 2;
    }
    puts(output);
    int shutdown_rc = guest_memory_shutdown();
    if (shutdown_rc) {
        fprintf(stderr, "guest_memory_shutdown: %d\n", shutdown_rc);
        return 2;
    }
    return rc ? 1 : 0;
}
