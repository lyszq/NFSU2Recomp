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
    TEB_ADDR = 0x00c00000u,
    LAST_ERROR_ADDR = TEB_ADDR + 0x34u,
    FRAME_CROSS = 0x00053ffcu,
    FRAME_UNMAPPED = 0x00070000u,
    PAGE_SIZE = GUEST_MEMORY_GRANULE,
    FEATURE_SSE = 6u,
    FEATURE_3DNOW = 7u,
    FEATURE_SSE2 = 10u,
    RETURN_ADDRESS = 0x00401234u,
    LAST_ERROR_SENTINEL = 0x13579bdfu
};

#define FRAME_TOP (UINT32_MAX - UINT32_C(3))

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

static void init_cpu(CPU *cpu, uint32_t esp, uint32_t fs_base) {
    memset(cpu, 0x69, sizeof(*cpu));
    cpu->eax = 0xaabbccddu;
    cpu->ecx = 0x12345678u;
    cpu->edx = 0x87654321u;
    cpu->ebx = 0x0badf00du;
    cpu->esp = esp;
    cpu->ebp = 0x55aa55aau;
    cpu->esi = 0xabcdef01u;
    cpu->edi = 0x10203040u;
    cpu->eip = 0x11223344u;
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x55667788u;
    eflags_set(cpu, 0x0cd5u);
}

static int write_frame(uint32_t address, uint32_t ret, uint32_t feature) {
    const uint32_t frame[2] = { ret, feature };
    return write_bytes(address, frame, sizeof(frame));
}

static int expect_completed_cpu(const CPU *actual, const CPU *before,
                                uint32_t ret, uint32_t result) {
    CPU expected = *before;
    expected.eax = result;
    expected.eip = ret;
    expected.esp = before->esp + 8u;
    if (memcmp(actual, &expected, sizeof(expected)) == 0) return 0;
    fprintf(stderr,
            "FAIL %s:%d: import changed CPU beyond EAX/EIP/ESP "
            "(EAX=%08x EIP=%08x ESP=%08x)\n",
            __FILE__, __LINE__, actual->eax, actual->eip, actual->esp);
    return 1;
}

static int expect_unchanged_cpu(const CPU *actual, const CPU *before) {
    if (memcmp(actual, before, sizeof(*actual)) == 0) return 0;
    fprintf(stderr, "FAIL %s:%d: unsupported or faulted import changed CPU\n",
            __FILE__, __LINE__);
    return 1;
}

static GuestImport feature_import(const char *library, const char *name) {
    GuestImport import = { 0xf0002468u, library, name };
    return import;
}

static int run_supported_prepared(uint32_t frame, uint32_t fs_base,
                                  uint32_t result) {
    CPU cpu, before;
    uint8_t frame_before[8], frame_after[8];
    uint32_t fault = 0xcafebabeu, last_error = 0;
    GuestImport import = feature_import("KERNEL32.dll",
                                        "IsProcessorFeaturePresent");

    CHECK(read_bytes(frame, frame_before, sizeof(frame_before)) == 0);
    CHECK(write_u32(LAST_ERROR_ADDR, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, frame, fs_base);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS, result) == 0);
    CHECK(read_bytes(frame, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    CHECK(read_bytes(LAST_ERROR_ADDR, &last_error, sizeof(last_error)) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    return 0;
}

static int run_supported(uint32_t frame, uint32_t fs_base,
                         uint32_t feature, uint32_t result) {
    CHECK(write_frame(frame, RETURN_ADDRESS, feature) == 0);
    return run_supported_prepared(frame, fs_base, result);
}

static int test_supported_feature(void) {
    CHECK(guest_memory_commit(TEB_ADDR, PAGE_SIZE) == 0);
    CHECK(write_u32(LAST_ERROR_ADDR, LAST_ERROR_SENTINEL) == 0);

    /* The call is stdcall, reads an unaligned frame, and preserves all else. */
    CHECK(run_supported(STACK_ADDR, TEB_ADDR, FEATURE_3DNOW, 0) == 0);

    /* Neither a valid TEB nor a writable TEB is required for feature 7. */
    CHECK(run_supported(STACK_ADDR, 0xdead0000u, FEATURE_3DNOW, 0) == 0);
    CHECK(run_supported(STACK_ADDR, 0, FEATURE_3DNOW, 0) == 0);
    CHECK(run_supported(STACK_ADDR, UINT32_MAX - 0x10u, FEATURE_3DNOW, 0) == 0);

    /* Read-only frame memory is sufficient because the handler only reads it. */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, FEATURE_3DNOW) == 0);
    CHECK(guest_memory_protect(STACK_PAGE, PAGE_SIZE, GUEST_MEMORY_READ) == 0);
    CHECK(run_supported_prepared(STACK_ADDR, 0xdead0000u, 0) == 0);
    CHECK(guest_memory_commit(STACK_PAGE, PAGE_SIZE) == 0);
    return 0;
}

static int test_static_processor_features(void) {
    static const struct {
        uint32_t feature;
        uint32_t available;
    } features[] = {
        { FEATURE_SSE, 1u },
        { FEATURE_SSE2, 0u }
    };

    for (size_t i = 0; i < sizeof(features) / sizeof(features[0]); ++i) {
        /* EDX 0x0383fbff has bit 25 (SSE) set, but bit 26 (SSE2) clear. */
        CHECK(run_supported(STACK_ADDR, TEB_ADDR,
                            features[i].feature, features[i].available) == 0);
        /* Constant results do not require probing the guest TEB. */
        CHECK(run_supported(STACK_ADDR, 0,
                            features[i].feature, features[i].available) == 0);
    }
    return 0;
}

static int test_unknown_features_and_imports(void) {
    static const uint32_t unknown_features[] = { 0, 8, 0xffffffffu };
    CPU cpu, before;
    uint8_t frame_before[8], frame_after[8];
    uint32_t fault = 0xabcdef12u;
    GuestImport supported = feature_import("KERNEL32.dll",
                                           "IsProcessorFeaturePresent");
    GuestImport wrong_library = feature_import("ADVAPI32.dll",
                                               "IsProcessorFeaturePresent");
    GuestImport wrong_name = feature_import("KERNEL32.dll",
                                            "IsProcessorFeaturePresentW");
    GuestImport wrong_case = feature_import("KERNEL32.dll",
                                            "isProcessorFeaturePresent");

    for (size_t i = 0; i < sizeof(unknown_features) / sizeof(unknown_features[0]); ++i) {
        CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, unknown_features[i]) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
        init_cpu(&cpu, STACK_ADDR, 0xdead0000u);
        before = cpu;
        CHECK(guest_windows_import(&cpu, &supported, NULL, &fault) == 0);
        CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
        CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
        CHECK(fault == 0xabcdef12u);
    }

    /* Unknown API/DLL tags are declined before touching even a bad stack. */
    init_cpu(&cpu, FRAME_UNMAPPED, 0xdead0000u);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &wrong_library, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, &wrong_name, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, &wrong_case, NULL, &fault) == 0);
    CHECK(guest_windows_import(&cpu, NULL, NULL, &fault) == 0);
    CHECK(guest_windows_import(NULL, &supported, NULL, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(fault == 0xabcdef12u);
    {
        uint32_t last_error = 0;
        CHECK(read_bytes(LAST_ERROR_ADDR, &last_error, sizeof(last_error)) == 0);
        CHECK(last_error == LAST_ERROR_SENTINEL);
    }
    return 0;
}

static int expect_frame_fault(uint32_t frame, uint32_t expected_fault,
                              size_t readable_prefix) {
    CPU cpu, before;
    uint8_t prefix_before[4], prefix_after[4];
    uint32_t fault = 0xfeedfaceu;
    GuestImport import = feature_import("KERNEL32.dll",
                                        "IsProcessorFeaturePresent");

    CHECK(readable_prefix <= sizeof(prefix_before));
    if (readable_prefix) CHECK(read_bytes(frame, prefix_before, readable_prefix) == 0);
    init_cpu(&cpu, frame, 0xdead0000u);
    before = cpu;
    CHECK(guest_windows_import(&cpu, &import, NULL, &fault) == -1);
    CHECK(fault == expected_fault);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    if (readable_prefix) {
        CHECK(read_bytes(frame, prefix_after, readable_prefix) == 0);
        CHECK(memcmp(prefix_before, prefix_after, readable_prefix) == 0);
    }
    return 0;
}

static int test_frame_memory_faults(void) {
    uint32_t ret = RETURN_ADDRESS;

    CHECK(guest_memory_commit(0x00050000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0xffffc000u, PAGE_SIZE) == 0);

    /* Entirely unmapped, one-byte-crossing, and 4 GiB-overflowing frames. */
    CHECK(expect_frame_fault(FRAME_UNMAPPED, FRAME_UNMAPPED, 0) == 0);
    CHECK(write_u32(FRAME_CROSS, ret) == 0);
    CHECK(expect_frame_fault(FRAME_CROSS, FRAME_CROSS, sizeof(ret)) == 0);
    CHECK(write_u32(FRAME_TOP, ret) == 0);
    CHECK(expect_frame_fault(FRAME_TOP, FRAME_TOP, sizeof(ret)) == 0);
    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_PAGE, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x00020000u, PAGE_SIZE) == 0);

    CHECK(test_supported_feature() == 0);
    CHECK(test_static_processor_features() == 0);
    CHECK(test_unknown_features_and_imports() == 0);
    CHECK(test_frame_memory_faults() == 0);
    CHECK(guest_memory_shutdown() == 0);
    puts("PASS processor feature import");
    return 0;
}
