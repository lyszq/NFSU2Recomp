#include "cpu.h"
#include "guest_execution.h"
#include "guest_memory.h"
#include "guest_registry.h"

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
    STRING_ADDR = 0x00020000u,
    OUTPUT_ADDR = 0x00030005u,
    TEB_ADDR = 0x00c00000u,
    LAST_ERROR_OFFSET = 0x34u,
    RET_ADDR = 0x00401234u,
    PAGE_SIZE = GUEST_MEMORY_GRANULE,
    STRING_LIMIT = 4096u
};

static const uint32_t predefined_roots[] = {
    UINT32_C(0x80000000), UINT32_C(0x80000001), UINT32_C(0x80000002),
    UINT32_C(0x80000003), UINT32_C(0x80000005)
};

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

static int write_string(uint32_t address, const char *string) {
    return write_bytes(address, string, strlen(string) + 1u);
}

static void init_cpu(CPU *cpu, uint32_t stack, uint32_t fs_base) {
    memset(cpu, 0x5a, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = stack;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = 0x88888888u;
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x99999999u;
    cpu->cf = 1;
    cpu->pf = 0;
    cpu->af = 1;
    cpu->zf = 0;
    cpu->sf = 1;
    cpu->of = 0;
    cpu->df = 1;
}

static int write_frame(uint32_t stack, uint32_t ret, uint32_t key,
                       uint32_t subkey, uint32_t result) {
    uint32_t frame[4] = { ret, key, subkey, result };
    return write_bytes(stack, frame, sizeof(frame));
}

static int expect_cpu_unchanged(const CPU *actual, const CPU *before) {
    if (memcmp(actual, before, sizeof(*actual)) == 0) return 0;
    fprintf(stderr, "FAIL %s:%d: CPU changed on unsupported/faulted call\n",
            __FILE__, __LINE__);
    return 1;
}

static int expect_cpu_completed(const CPU *actual, const CPU *before,
                                uint32_t ret, uint32_t status) {
    CPU expected = *before;
    expected.eax = status;
    expected.eip = ret;
    expected.esp = before->esp + 16u;
    if (memcmp(actual, &expected, sizeof(expected)) == 0) return 0;
    fprintf(stderr,
            "FAIL %s:%d: completed call changed CPU beyond EAX/EIP/ESP "
            "(EAX=%08x EIP=%08x ESP=%08x)\n",
            __FILE__, __LINE__, actual->eax, actual->eip, actual->esp);
    return 1;
}

static GuestImport make_import(const char *library, const char *name) {
    GuestImport import;
    import.iat = 0xf1234567u;
    import.library = library;
    import.name = name;
    return import;
}

static int run_completed(uint32_t key, uint32_t subkey, uint32_t result,
                         uint32_t status, uint32_t result_handle,
                         uint32_t fs_base, const char *library) {
    const uint32_t ret = RET_ADDR;
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, actual = 0;
    GuestImport import = make_import(library, "RegOpenKeyA");

    CHECK(write_frame(STACK_ADDR, ret, key, subkey, result) == 0);
    CHECK(write_u32(result, 0xa5a5a5a5u) == 0);
    init_cpu(&cpu, STACK_ADDR, fs_base);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, ret, status) == 0);
    CHECK(read_u32(result, &actual) == 0);
    CHECK(actual == result_handle);
    if (fs_base == TEB_ADDR) {
        CHECK(read_u32(TEB_ADDR + LAST_ERROR_OFFSET, &actual) == 0);
        CHECK(actual == 0x13579bdfu);
    }
    return 0;
}

static int test_predefined_roots_and_missing_subkeys(void) {
    static const char *const absent_names[] = {
        "Software\\EA Games\\Need for Speed Underground 2",
        "software\\ea games\\need for speed underground 2",
        "ThisNameIsNotPresent\\DifferentCase"
    };
    uint32_t actual = 0;

    /* A valid TEB contains a sentinel LastError that this API must preserve. */
    CHECK(guest_memory_commit(TEB_ADDR, PAGE_SIZE) == 0);
    CHECK(write_u32(TEB_ADDR + LAST_ERROR_OFFSET, 0x13579bdfu) == 0);
    CHECK(guest_memory_commit(STRING_ADDR, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(OUTPUT_ADDR & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);

    for (size_t i = 0; i < sizeof(predefined_roots) / sizeof(predefined_roots[0]); ++i) {
        uint32_t root = predefined_roots[i];
        CHECK(run_completed(root, 0, OUTPUT_ADDR, 0, root, TEB_ADDR,
                            "aDvApI32.DlL") == 0);
        CHECK(read_u32(TEB_ADDR + LAST_ERROR_OFFSET, &actual) == 0);
        CHECK(actual == 0x13579bdfu);

        CHECK(write_string(STRING_ADDR, "") == 0);
        CHECK(run_completed(root, STRING_ADDR, OUTPUT_ADDR, 0, root, TEB_ADDR,
                            "ADVAPI32.dll") == 0);

        for (size_t n = 0; n < sizeof(absent_names) / sizeof(absent_names[0]); ++n) {
            CHECK(write_string(STRING_ADDR, absent_names[n]) == 0);
            CHECK(run_completed(root, STRING_ADDR, OUTPUT_ADDR, 2, 0, TEB_ADDR,
                                "ADVAPI32.dll") == 0);
        }
    }
    return 0;
}

static int test_invalid_handles_and_teb_independence(void) {
    static const uint32_t invalid_keys[] = {
        0, UINT32_C(0xdeadbeef), UINT32_C(0x80000004), UINT32_C(0x80000006)
    };

    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); ++i) {
        CHECK(run_completed(invalid_keys[i], 0, OUTPUT_ADDR, 6, 0,
                            TEB_ADDR, "ADVAPI32.dll") == 0);
    }
    CHECK(write_string(STRING_ADDR, "A valid but absent subkey") == 0);
    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); ++i) {
        CHECK(run_completed(invalid_keys[i], STRING_ADDR, OUTPUT_ADDR, 6, 0,
                            TEB_ADDR, "ADVAPI32.dll") == 0);
    }

    /* An unmapped, overflowing, or null FS base is not consulted by this API. */
    CHECK(run_completed(predefined_roots[0], 0, OUTPUT_ADDR, 0,
                        predefined_roots[0], 0xdead0000u,
                        "ADVAPI32.dll") == 0);
    CHECK(run_completed(predefined_roots[1], 0, OUTPUT_ADDR, 0,
                        predefined_roots[1], UINT32_MAX - 0x10u,
                        "ADVAPI32.dll") == 0);
    CHECK(run_completed(predefined_roots[2], 0, OUTPUT_ADDR, 0,
                        predefined_roots[2], 0,
                        "ADVAPI32.dll") == 0);
    return 0;
}

static int test_aliases_and_unaligned_result(void) {
    CPU cpu, before;
    uint32_t fault = 0xdeadbeefu, actual = 0;
    GuestImport import = make_import("ADVAPI32.dll", "RegOpenKeyA");

    /* The name aliases the return-address bytes; output aliases the hkey slot.
     * Both arguments and the return address must be snapshotted before writing. */
    const uint32_t ret = 0x00401200u; /* Its first little-endian byte is NUL. */
    CHECK(write_frame(STACK_ADDR, ret, predefined_roots[3], STACK_ADDR,
                      STACK_ADDR + 4u) == 0);
    init_cpu(&cpu, STACK_ADDR, 0xdead0000u);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, ret, 0) == 0);
    CHECK(read_u32(STACK_ADDR + 4u, &actual) == 0);
    CHECK(actual == predefined_roots[3]);

    /* Here the output DWORD aliases the input C string itself. */
    CHECK(write_u32(OUTPUT_ADDR, 0) == 0);
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[4], OUTPUT_ADDR,
                      OUTPUT_ADDR) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, RET_ADDR, 0) == 0);
    CHECK(read_u32(OUTPUT_ADDR, &actual) == 0);
    CHECK(actual == predefined_roots[4]);

    /* Output aliases the return slot: EIP still receives the original return. */
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[0], 0,
                      STACK_ADDR) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, RET_ADDR, 0) == 0);
    CHECK(read_u32(STACK_ADDR, &actual) == 0);
    CHECK(actual == predefined_roots[0]);

    /* A result pointer need not be DWORD-aligned. */
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[1], 0,
                      OUTPUT_ADDR + 1u) == 0);
    CHECK(write_u32(OUTPUT_ADDR + 1u, 0xccccccccu) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, RET_ADDR, 0) == 0);
    CHECK(read_u32(OUTPUT_ADDR + 1u, &actual) == 0);
    CHECK(actual == predefined_roots[1]);
    return 0;
}

static int check_faulted_call(uint32_t stack, uint32_t key, uint32_t subkey,
                              uint32_t result, uint32_t expected_fault,
                              size_t result_size) {
    CPU cpu, before;
    uint8_t frame_before[16], frame_after[16];
    uint8_t output_before[8], output_after[8];
    uint32_t fault = 0xabcdef01u;
    GuestImport import = make_import("ADVAPI32.dll", "RegOpenKeyA");

    CHECK(write_frame(stack, RET_ADDR, key, subkey, result) == 0);
    CHECK(read_bytes(stack, frame_before, sizeof(frame_before)) == 0);
    CHECK(result_size <= sizeof(output_before));
    if (result_size) CHECK(read_bytes(result, output_before, result_size) == 0);
    init_cpu(&cpu, stack, 0xdead0000u);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == -1);
    CHECK(fault == expected_fault);
    CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
    CHECK(read_bytes(stack, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
    if (result_size) {
        CHECK(read_bytes(result, output_after, result_size) == 0);
        CHECK(memcmp(output_before, output_after, result_size) == 0);
    }
    return 0;
}

static int test_frame_string_and_output_faults(void) {
    const uint32_t ro_output = 0x00060020u;
    const uint32_t cross_output = 0x00073ffeu;
    const uint32_t wrap_output = UINT32_MAX - 1u;
    const uint32_t str_fault = 0x000b3fffu;
    uint8_t edge[2] = { 0xa5, 0x5a };

    CHECK(guest_memory_commit(0x00080000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x00090000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x000b0000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0x00070000u, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(ro_output & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(0xffffc000u, PAGE_SIZE) == 0);

    CHECK(write_u32(ro_output, 0xfacecafeu) == 0);
    CHECK(guest_memory_protect(ro_output, sizeof(uint32_t), GUEST_MEMORY_READ) == 0);
    CHECK(check_faulted_call(STACK_ADDR, predefined_roots[0], 0, ro_output,
                             ro_output, sizeof(uint32_t)) == 0);
    CHECK(guest_memory_commit(ro_output & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);

    CHECK(write_bytes(cross_output, edge, sizeof(edge)) == 0);
    CHECK(check_faulted_call(STACK_ADDR, predefined_roots[0], 0, cross_output,
                             cross_output, sizeof(edge)) == 0);

    CHECK(write_bytes(wrap_output, edge, sizeof(edge)) == 0);
    CHECK(check_faulted_call(STACK_ADDR, predefined_roots[0], 0, wrap_output,
                             wrap_output, sizeof(edge)) == 0);

    CHECK(check_faulted_call(STACK_ADDR, predefined_roots[0], 0, 0, 0,
                             0) == 0);

    /* The first byte is readable; the next byte crosses into an unmapped page. */
    CHECK(write_bytes(str_fault, "X", 1) == 0);
    CHECK(write_u32(OUTPUT_ADDR, 0x12345678u) == 0);
    CHECK(check_faulted_call(STACK_ADDR, predefined_roots[0], str_fault,
                             OUTPUT_ADDR, str_fault + 1u,
                             sizeof(uint32_t)) == 0);

    /* String preflight runs even when the root handle itself is invalid. */
    CHECK(check_faulted_call(STACK_ADDR, UINT32_C(0xdeadbeef),
                             0x000d0000u, OUTPUT_ADDR, 0x000d0000u,
                             sizeof(uint32_t)) == 0);

    /* An uncommitted call frame faults at ESP without changing CPU state. */
    {
        CPU cpu, before;
        uint32_t fault = 0;
        GuestImport import = make_import("ADVAPI32.dll", "RegOpenKeyA");
        init_cpu(&cpu, 0x000d0000u, 0xdead0000u);
        before = cpu;
        CHECK(guest_registry_import(&cpu, &import, &fault) == -1);
        CHECK(fault == 0x000d0000u);
        CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
    }

    /* A frame range that would wrap past 4 GiB also faults at its base. */
    {
        CPU cpu, before;
        uint32_t fault = 0;
        GuestImport import = make_import("ADVAPI32.dll", "RegOpenKeyA");
        init_cpu(&cpu, UINT32_MAX - 7u, 0xdead0000u);
        before = cpu;
        CHECK(guest_registry_import(&cpu, &import, &fault) == -1);
        CHECK(fault == UINT32_MAX - 7u);
        CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
    }
    return 0;
}

static int test_cross_page_and_bounded_strings(void) {
    const uint32_t split_name = 0x00083fffu;
    const uint32_t cap_name = 0x000a0000u;
    const uint32_t top_name = UINT32_MAX - 3u;
    CPU cpu, before;
    GuestImport import = make_import("ADVAPI32.dll", "RegOpenKeyA");
    uint32_t fault = 0xfeedfaceu, actual = 0;

    /* One-character name and NUL split across two readable pages. */
    CHECK(write_bytes(split_name, "x", 1) == 0);
    CHECK(guest_memory_commit(0x00084000u, PAGE_SIZE) == 0);
    CHECK(write_bytes(0x00084000u, "\0", 1) == 0);
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[0], split_name,
                      OUTPUT_ADDR) == 0);
    init_cpu(&cpu, STACK_ADDR, 0xdead0000u);
    before = cpu;
    CHECK(guest_registry_import(&cpu, &import, &fault) == 1);
    CHECK(expect_cpu_completed(&cpu, &before, RET_ADDR, 2) == 0);
    CHECK(read_u32(OUTPUT_ADDR, &actual) == 0 && actual == 0);

    /* No terminator in the 4096-byte scan budget: unsupported, no mutation.
     * A NUL immediately after the cap proves the handler stops at the limit. */
    CHECK(guest_memory_commit(cap_name, PAGE_SIZE) == 0);
    {
        uint8_t long_name[STRING_LIMIT + 1u];
        memset(long_name, 'Q', STRING_LIMIT);
        long_name[STRING_LIMIT] = 0;
        CHECK(write_bytes(cap_name, long_name, sizeof(long_name)) == 0);
    }
    CHECK(write_u32(OUTPUT_ADDR, 0x76543210u) == 0);
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[0], cap_name,
                      OUTPUT_ADDR) == 0);
    {
        uint8_t frame_before[16], frame_after[16];
        uint32_t output_before = 0;
        CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
        CHECK(read_u32(OUTPUT_ADDR, &output_before) == 0);
        init_cpu(&cpu, STACK_ADDR, 0xdead0000u);
        before = cpu;
        fault = 0xfeedfaceu;
        CHECK(guest_registry_import(&cpu, &import, &fault) == 0);
        CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
        CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
        CHECK(read_u32(OUTPUT_ADDR, &actual) == 0 && actual == output_before);
        CHECK(fault == 0xfeedfaceu);
    }

    /* 64-bit address arithmetic must not wrap this unterminated string to 0. */
    CHECK(guest_memory_commit(0, PAGE_SIZE) == 0);
    CHECK(write_bytes(0, "\0", 1) == 0);
    CHECK(guest_memory_commit(0xffffc000u, PAGE_SIZE) == 0);
    {
        const uint8_t tail[4] = { 'N', 'O', 'P', 'E' };
        uint8_t frame_before[16], frame_after[16];
        uint32_t output_before = 0;
        CHECK(write_bytes(top_name, tail, sizeof(tail)) == 0);
        CHECK(write_u32(OUTPUT_ADDR, 0x87654321u) == 0);
        CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[0], top_name,
                          OUTPUT_ADDR) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
        CHECK(read_u32(OUTPUT_ADDR, &output_before) == 0);
        init_cpu(&cpu, STACK_ADDR, 0xdead0000u);
        before = cpu;
        fault = 0xfeedfaceu;
        CHECK(guest_registry_import(&cpu, &import, &fault) == -1);
        CHECK(fault == UINT32_MAX);
        CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
        CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
        CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);
        CHECK(read_u32(OUTPUT_ADDR, &actual) == 0 && actual == output_before);
    }
    return 0;
}

static int test_unsupported_imports_and_null_hosts(void) {
    CPU cpu, before;
    uint32_t fault = 0xabcdef12u, output_before = 0, output_after = 0;
    uint8_t frame_before[16], frame_after[16];
    GuestImport wrong_library = make_import("KERNEL32.dll", "RegOpenKeyA");
    GuestImport wrong_api = make_import("ADVAPI32.dll", "RegOpenKeyW");
    GuestImport wrong_case = make_import("ADVAPI32.dll", "regopenkeya");
    GuestImport null_library = make_import(NULL, "RegOpenKeyA");
    GuestImport null_name = make_import("ADVAPI32.dll", NULL);

    CHECK(write_u32(OUTPUT_ADDR, 0x11223344u) == 0);
    CHECK(write_frame(STACK_ADDR, RET_ADDR, predefined_roots[0], 0,
                      OUTPUT_ADDR) == 0);
    init_cpu(&cpu, 0x000d0000u, 0xdead0000u); /* Deliberately bad ESP. */
    before = cpu;
    CHECK(read_u32(OUTPUT_ADDR, &output_before) == 0);
    CHECK(read_bytes(STACK_ADDR, frame_before, sizeof(frame_before)) == 0);
    CHECK(guest_registry_import(&cpu, &wrong_library, &fault) == 0);
    CHECK(guest_registry_import(&cpu, &wrong_api, &fault) == 0);
    CHECK(guest_registry_import(&cpu, &wrong_case, &fault) == 0);
    CHECK(guest_registry_import(&cpu, &null_library, &fault) == 0);
    CHECK(guest_registry_import(&cpu, &null_name, &fault) == 0);
    CHECK(guest_registry_import(NULL, &wrong_api, &fault) == 0);
    CHECK(guest_registry_import(&cpu, NULL, &fault) == 0);
    CHECK(guest_registry_import(&cpu, &wrong_api, NULL) == 0);
    CHECK(fault == 0xabcdef12u);
    CHECK(expect_cpu_unchanged(&cpu, &before) == 0);
    CHECK(read_u32(OUTPUT_ADDR, &output_after) == 0);
    CHECK(output_after == output_before);
    CHECK(read_bytes(STACK_ADDR, frame_after, sizeof(frame_after)) == 0);
    CHECK(memcmp(frame_before, frame_after, sizeof(frame_before)) == 0);

    /* Wrong library/API tags remain unsupported even with null host strings. */
    CHECK(guest_registry_import(NULL, NULL, NULL) == 0);
    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(STACK_ADDR, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(STRING_ADDR, PAGE_SIZE) == 0);
    CHECK(guest_memory_commit(OUTPUT_ADDR & ~(PAGE_SIZE - 1u), PAGE_SIZE) == 0);

    CHECK(test_predefined_roots_and_missing_subkeys() == 0);
    CHECK(test_invalid_handles_and_teb_independence() == 0);
    CHECK(test_aliases_and_unaligned_result() == 0);
    CHECK(test_frame_string_and_output_faults() == 0);
    CHECK(test_cross_page_and_bounded_strings() == 0);
    CHECK(test_unsupported_imports_and_null_hosts() == 0);
    CHECK(guest_memory_shutdown() == 0);
    puts("PASS guest registry import");
    return 0;
}
