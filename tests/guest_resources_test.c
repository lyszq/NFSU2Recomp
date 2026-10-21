#include "cpu.h"
#include "guest_execution.h"
#include "guest_memory.h"
#include "guest_pe.h"
#include "guest_resources.h"

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
    IMAGE_BASE = 0x00400000u,
    IMAGE_SIZE = 0x00004000u,
    RESOURCE_RVA = 0x100u,
    RESOURCE_SIZE = 0x400u,
    IMAGE_PAYLOAD_RVA = 0x800u,
    STACK_ADDR = 0x00100003u,
    READONLY_STACK = 0x00110003u,
    TEB_ADDR = 0x00200000u,
    LAST_ERROR_OFFSET = 0x34u,
    LAST_ERROR_ADDRESS = TEB_ADDR + LAST_ERROR_OFFSET,
    RETURN_ADDRESS = 0x00401234u,
    LAST_ERROR_SENTINEL = 0x13579bdfu,
    ERROR_RESOURCE_TYPE_NOT_FOUND = 1813u,
    RT_GROUP_ICON = 14u,
    IDI_APPLICATION = 32512u,
    UNMAPPED_IMAGE_BASE = 0x00800000u
};

#define IMAGE_RESOURCE_BASE (IMAGE_BASE + RESOURCE_RVA)

static const GuestImport LOAD_ICON = { 0xf0004321u, "uSeR32.dLl", "LoadIconA" };

static int write_bytes(uint32_t address, const void *bytes, size_t size)
{
    void *destination = guest_memory_pointer(address, size, 1);
    if (!destination) return 1;
    memcpy(destination, bytes, size);
    return 0;
}

static int read_bytes(uint32_t address, void *bytes, size_t size)
{
    const void *source = guest_memory_pointer(address, size, 0);
    if (!source) return 1;
    memcpy(bytes, source, size);
    return 0;
}

static int write_u32(uint32_t address, uint32_t value)
{
    return write_bytes(address, &value, sizeof(value));
}

static int read_u32_guest(uint32_t address, uint32_t *value)
{
    return read_bytes(address, value, sizeof(*value));
}

static void put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int put_resource_bytes(uint32_t offset, const void *bytes, size_t size)
{
    if ((uint64_t)offset + size > RESOURCE_SIZE) return 1;
    return write_bytes(IMAGE_RESOURCE_BASE + offset, bytes, size);
}

static int put_directory(uint32_t offset, uint16_t named_count,
                         uint16_t id_count)
{
    uint8_t header[16] = { 0 };
    put_u16(header + 12u, named_count);
    put_u16(header + 14u, id_count);
    return put_resource_bytes(offset, header, sizeof(header));
}

static int put_entry(uint32_t directory_offset, uint32_t index,
                     uint32_t name, uint32_t target)
{
    uint8_t entry[8];
    put_u32(entry, name);
    put_u32(entry + 4u, target);
    return put_resource_bytes(directory_offset + 16u + index * 8u,
                              entry, sizeof(entry));
}

static int put_resource_name(uint32_t offset, const char *ascii)
{
    const size_t length = strlen(ascii);
    uint8_t encoded[2u + 2u * 32u] = { 0 };
    if (length > 32u) return 1;
    put_u16(encoded, (uint16_t)length);
    for (size_t i = 0; i < length; ++i) {
        encoded[2u + 2u * i] = (uint8_t)ascii[i];
    }
    return put_resource_bytes(offset, encoded, 2u + 2u * length);
}

static void init_cpu(CPU *cpu, uint32_t esp, uint32_t fs_base)
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
    cpu->fs_base = fs_base;
    cpu->gs_base = 0x99887766u;
    cpu->cf = 1;
    cpu->pf = 0;
    cpu->af = 1;
    cpu->zf = 0;
    cpu->sf = 1;
    cpu->of = 0;
    cpu->df = 1;
}

static int write_frame(uint32_t stack, uint32_t return_ip, uint32_t module,
                       uint32_t icon_id)
{
    const uint32_t frame[3] = { return_ip, module, icon_id };
    return write_bytes(stack, frame, sizeof(frame));
}

static int expect_unchanged_cpu(const CPU *actual, const CPU *before)
{
    if (memcmp(actual, before, sizeof(*actual)) == 0) return 0;
    fprintf(stderr, "FAIL %s:%d: CPU changed on unsupported/faulted call\n",
            __FILE__, __LINE__);
    return 1;
}

static int expect_completed_cpu(const CPU *actual, const CPU *before,
                                uint32_t return_ip)
{
    CPU expected = *before;
    expected.eax = 0u;
    expected.eip = return_ip;
    expected.esp = before->esp + 12u;
    if (memcmp(actual, &expected, sizeof(expected)) == 0) return 0;
    fprintf(stderr,
            "FAIL %s:%d: LoadIconA changed CPU beyond EAX/EIP/ESP\n",
            __FILE__, __LINE__);
    return 1;
}

static GuestPEImage image_metadata(void)
{
    GuestPEImage image = {
        .image_base = IMAGE_BASE,
        .image_size = IMAGE_SIZE,
        .entry_point = IMAGE_BASE + 0x1000u,
        .resource_address = IMAGE_RESOURCE_BASE,
        .resource_size = RESOURCE_SIZE,
        .section_count = 1u
    };
    return image;
}

static int reset_resource_bytes(void)
{
    uint8_t empty[RESOURCE_SIZE] = { 0 };
    return put_resource_bytes(0u, empty, sizeof(empty));
}

/* The image has a named root type and no numeric RT_GROUP_ICON entry. */
static int build_named_root_type_only(void)
{
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 1u, 0u) == 0);
    CHECK(put_entry(0u, 0u, 0x80000200u, 0x80000020u) == 0);
    CHECK(put_resource_name(0x200u, "GROUP_ICON") == 0);
    CHECK(put_directory(0x20u, 0u, 0u) == 0);
    return 0;
}

/* RT_GROUP_ICON exists, but its only child has a name rather than numeric
 * IDI_APPLICATION. This must not be confused with a present numeric ID. */
static int build_named_icon_only(void)
{
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000020u) == 0);
    CHECK(put_directory(0x20u, 1u, 0u) == 0);
    CHECK(put_entry(0x20u, 0u, 0x80000180u, 0x80000060u) == 0);
    CHECK(put_resource_name(0x180u, "APPICON") == 0);
    CHECK(put_directory(0x60u, 0u, 0u) == 0);
    return 0;
}

static int build_numeric_application_icon(void)
{
    uint8_t data_entry[16] = { 0 };
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000020u) == 0);
    CHECK(put_directory(0x20u, 0u, 1u) == 0);
    CHECK(put_entry(0x20u, 0u, IDI_APPLICATION, 0x80000060u) == 0);
    CHECK(put_directory(0x60u, 0u, 1u) == 0);
    CHECK(put_entry(0x60u, 0u, 0x0409u, 0x000000a0u) == 0);
    put_u32(data_entry, IMAGE_PAYLOAD_RVA);
    put_u32(data_entry + 4u, 4u);
    CHECK(put_resource_bytes(0xa0u, data_entry, sizeof(data_entry)) == 0);
    return 0;
}

static int setup_memory(void)
{
    CHECK(guest_memory_init() == 0);
    CHECK(guest_memory_commit(IMAGE_BASE, IMAGE_SIZE) == 0);
    CHECK(guest_memory_commit(STACK_ADDR & ~(GUEST_MEMORY_GRANULE - 1u),
                              GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(READONLY_STACK &
                              ~(GUEST_MEMORY_GRANULE - 1u),
                              GUEST_MEMORY_GRANULE) == 0);
    CHECK(guest_memory_commit(TEB_ADDR, GUEST_MEMORY_GRANULE) == 0);
    return 0;
}

static int test_missing_numeric_resource_completes(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;

    CHECK(build_named_root_type_only() == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == ERROR_RESOURCE_TYPE_NOT_FOUND);
    CHECK(fault == 0xcafebabeu);

    CHECK(build_named_icon_only() == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == ERROR_RESOURCE_TYPE_NOT_FOUND);
    return 0;
}

static int test_present_numeric_resource_stops(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xdecafbadU, last_error = 0;
    CHECK(build_numeric_application_icon() == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;

    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    CHECK(fault == 0xdecafbadU);
    return 0;
}

static int test_image_without_resource_directory(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;
    image.resource_address = 0u;
    image.resource_size = 0u;
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;

    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == ERROR_RESOURCE_TYPE_NOT_FOUND);
    return 0;
}

static int test_malformed_and_inaccessible_resources_stop(void)
{
    GuestPEImage image = image_metadata();
    GuestPEImage malformed = image;
    GuestPEImage inaccessible = {
        .image_base = UNMAPPED_IMAGE_BASE,
        .image_size = GUEST_MEMORY_GRANULE,
        .entry_point = UNMAPPED_IMAGE_BASE,
        .resource_address = UNMAPPED_IMAGE_BASE,
        .resource_size = 0x100u,
        .section_count = 1u
    };
    CPU cpu, before;
    uint32_t fault = 0x13572468u, last_error = 0;

    CHECK(build_named_root_type_only() == 0);
    malformed.resource_size = 20u; /* Root table needs 24 bytes. */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &malformed, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);

    /* A readable directory with an out-of-span named-resource string is
     * malformed, not proof that the requested numeric type is absent. */
    CHECK(build_named_root_type_only() == 0);
    CHECK(put_entry(0u, 0u, 0x800003ffu, 0x80000020u) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);

    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, inaccessible.image_base,
                      IDI_APPLICATION) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0x13572468u;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &inaccessible, &fault) == -1);
    CHECK(fault == inaccessible.resource_address);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    return 0;
}

static int test_named_id_flag_mismatch_stops(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;

    /* The named-entry count claims entry zero is a string, but it is ID 14.
     * A permissive scan would skip it and falsely report the type absent. */
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 1u, 0u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000020u) == 0);
    CHECK(put_directory(0x20u, 0u, 0u) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);

    /* The ID-entry count claims an integer ID, but the entry is a named
     * string. A permissive scan could skip that malformed group-type entry. */
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, 0x80000200u, 0x80000020u) == 0);
    CHECK(put_resource_name(0x200u, "GROUP_ICON") == 0);
    CHECK(put_directory(0x20u, 0u, 0u) == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    return 0;
}

static int assert_resource_cycle_is_unsupported(const GuestPEImage *image)
{
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;

    CHECK(guest_resources_import(&cpu, &LOAD_ICON, image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    return 0;
}

static int test_resource_directory_cycles_are_rejected(void)
{
    GuestPEImage image = image_metadata();

    /* Root RT_GROUP_ICON entry points to the root itself (offset zero). */
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000000u) == 0);
    CHECK(assert_resource_cycle_is_unsupported(&image) == 0);

    /* Root -> group-type directory -> ancestor root. */
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000020u) == 0);
    CHECK(put_directory(0x20u, 0u, 1u) == 0);
    CHECK(put_entry(0x20u, 0u, IDI_APPLICATION, 0x80000000u) == 0);
    CHECK(assert_resource_cycle_is_unsupported(&image) == 0);

    /* Root -> group-type directory -> that same group-type directory. */
    CHECK(reset_resource_bytes() == 0);
    CHECK(put_directory(0u, 0u, 1u) == 0);
    CHECK(put_entry(0u, 0u, RT_GROUP_ICON, 0x80000020u) == 0);
    CHECK(put_directory(0x20u, 0u, 1u) == 0);
    CHECK(put_entry(0x20u, 0u, IDI_APPLICATION, 0x80000020u) == 0);
    CHECK(assert_resource_cycle_is_unsupported(&image) == 0);
    return 0;
}

static int test_frame_preflight_and_dispatch(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;
    const GuestImport wrong_library = { 0, "KERNEL32.dll", "LoadIconA" };
    const GuestImport wrong_name = { 0, "USER32.dll", "LoadCursorA" };

    CHECK(build_named_root_type_only() == 0);
    init_cpu(&cpu, 0x00700000u, TEB_ADDR); /* No frame mapping. */
    before = cpu;
    CHECK(guest_resources_import(&cpu, &wrong_library, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(guest_resources_import(&cpu, &wrong_name, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(fault == 0xcafebabeu);

    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == -1);
    CHECK(fault == cpu.esp);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE + 0x1000u,
                      IDI_APPLICATION) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE, 32513u) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 0);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    /* The LastError target aliases the snapshotted module argument. */
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    init_cpu(&cpu, STACK_ADDR, STACK_ADDR - 0x30u);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    CHECK(read_u32_guest(STACK_ADDR + 4u, &last_error) == 0);
    CHECK(last_error == ERROR_RESOURCE_TYPE_NOT_FOUND);
    return 0;
}

static int test_last_error_preflight(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu, last_error = 0;

    CHECK(build_named_root_type_only() == 0);
    CHECK(write_frame(STACK_ADDR, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    init_cpu(&cpu, STACK_ADDR, 0u);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == -2);
    CHECK(fault == 0u);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    init_cpu(&cpu, STACK_ADDR, 0x00700000u); /* Valid base, unmapped TEB. */
    before = cpu;
    fault = 0xcafebabeu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == -1);
    CHECK(fault == 0x00700034u);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    init_cpu(&cpu, STACK_ADDR, UINT32_MAX - 0x34u);
    before = cpu;
    fault = 0xcafebabeu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == -1);
    CHECK(fault == UINT32_MAX - 0u);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);

    CHECK(write_u32(LAST_ERROR_ADDRESS, LAST_ERROR_SENTINEL) == 0);
    CHECK(guest_memory_protect(TEB_ADDR, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_READ) == 0);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    fault = 0xcafebabeu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == -1);
    CHECK(fault == LAST_ERROR_ADDRESS);
    CHECK(expect_unchanged_cpu(&cpu, &before) == 0);
    CHECK(read_u32_guest(LAST_ERROR_ADDRESS, &last_error) == 0);
    CHECK(last_error == LAST_ERROR_SENTINEL);
    return 0;
}

static int test_readonly_frame_is_allowed(void)
{
    GuestPEImage image = image_metadata();
    CPU cpu, before;
    uint32_t fault = 0xcafebabeu;
    CHECK(build_named_root_type_only() == 0);
    CHECK(write_frame(READONLY_STACK, RETURN_ADDRESS, IMAGE_BASE,
                      IDI_APPLICATION) == 0);
    CHECK(guest_memory_protect(READONLY_STACK &
                               ~(GUEST_MEMORY_GRANULE - 1u),
                               GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_READ) == 0);
    init_cpu(&cpu, READONLY_STACK, TEB_ADDR);
    before = cpu;
    CHECK(guest_resources_import(&cpu, &LOAD_ICON, &image, &fault) == 1);
    CHECK(expect_completed_cpu(&cpu, &before, RETURN_ADDRESS) == 0);
    return 0;
}

int main(void)
{
    CHECK(setup_memory() == 0);
    CHECK(test_missing_numeric_resource_completes() == 0);
    CHECK(test_present_numeric_resource_stops() == 0);
    CHECK(test_image_without_resource_directory() == 0);
    CHECK(test_malformed_and_inaccessible_resources_stop() == 0);
    CHECK(test_named_id_flag_mismatch_stops() == 0);
    CHECK(test_resource_directory_cycles_are_rejected() == 0);
    CHECK(test_frame_preflight_and_dispatch() == 0);
    CHECK(test_readonly_frame_is_allowed() == 0);
    CHECK(test_last_error_preflight() == 0);
    CHECK(guest_memory_shutdown() == 0);
    puts("PASS guest resources LoadIconA tests");
    return 0;
}
