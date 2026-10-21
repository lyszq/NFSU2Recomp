#include "guest_resources.h"

#include "guest_memory.h"

#include <stdint.h>
#include <string.h>
#include <strings.h>

#define LOADICONA_FRAME_SIZE 12u
#define LOADICONA_IDI_APPLICATION 32512u
#define RT_GROUP_ICON 14u
#define ERROR_RESOURCE_TYPE_NOT_FOUND 1813u
#define RESOURCE_DIRECTORY_HEADER_SIZE 16u
#define RESOURCE_DIRECTORY_ENTRY_SIZE 8u
#define RESOURCE_DATA_ENTRY_SIZE 16u
#define RESOURCE_ENTRY_LIMIT 4096u
#define RESOURCE_NAME_LIMIT 4096u

enum ResourceScanResult {
    RESOURCE_SCAN_FAULT = -1,
    RESOURCE_SCAN_INVALID = 0,
    RESOURCE_SCAN_ABSENT = 1,
    RESOURCE_SCAN_PRESENT = 2
};

typedef struct ResourceDirectory {
    const uint8_t *bytes;
    uint32_t offset;
    uint32_t named_count;
    uint32_t id_count;
    uint32_t entry_count;
} ResourceDirectory;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | (uint16_t)bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static int resource_span_valid(const GuestPEImage *image)
{
    const uint64_t image_end = (uint64_t)image->image_base + image->image_size;
    if (!image->image_base || !image->image_size ||
        image_end > GUEST_MEMORY_SIZE) {
        return 0;
    }
    if (!image->resource_address && !image->resource_size) {
        return 1; /* A valid image with no resource directory. */
    }
    if (!image->resource_address || !image->resource_size ||
        image->resource_address < image->image_base) {
        return 0;
    }
    const uint64_t resource_end = (uint64_t)image->resource_address +
                                  image->resource_size;
    return resource_end <= image_end && resource_end <= GUEST_MEMORY_SIZE;
}

/* Read bytes only from the declared resource-directory span. A range outside
 * that span is malformed metadata; an inaccessible in-span range is a guest
 * memory fault. */
static int resource_bytes(const GuestPEImage *image, uint32_t offset,
                          uint32_t size, const uint8_t **bytes,
                          uint32_t *fault)
{
    if ((uint64_t)offset + size > image->resource_size) {
        return RESOURCE_SCAN_INVALID;
    }
    const uint64_t address = (uint64_t)image->resource_address + offset;
    if (address > UINT32_MAX || (size && address + size > GUEST_MEMORY_SIZE)) {
        return RESOURCE_SCAN_INVALID;
    }
    const uint8_t *pointer = (const uint8_t *)guest_memory_pointer(
        (uint32_t)address, size, 0);
    if (!pointer) {
        *fault = (uint32_t)address;
        return RESOURCE_SCAN_FAULT;
    }
    *bytes = pointer;
    return RESOURCE_SCAN_PRESENT;
}

static int name_view(const GuestPEImage *image, uint32_t name,
                     const uint8_t **characters, uint32_t *length,
                     uint32_t *fault)
{
    if (!(name & UINT32_C(0x80000000))) {
        if (name & UINT32_C(0x7fff0000)) return RESOURCE_SCAN_INVALID;
        *characters = NULL;
        *length = 0u;
        return RESOURCE_SCAN_PRESENT;
    }

    const uint32_t offset = name & UINT32_C(0x7fffffff);
    const uint8_t *length_bytes = NULL;
    int rc = resource_bytes(image, offset, 2u, &length_bytes, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;
    *length = read_u16(length_bytes);
    if (*length > RESOURCE_NAME_LIMIT) return RESOURCE_SCAN_INVALID;
    if (!*length) {
        *characters = NULL;
        return RESOURCE_SCAN_PRESENT;
    }
    return resource_bytes(image, offset + 2u, *length * 2u,
                          characters, fault);
}

static int compare_named_entries(const GuestPEImage *image, uint32_t left,
                                 uint32_t right, int *comparison,
                                 uint32_t *fault)
{
    const uint8_t *left_chars = NULL, *right_chars = NULL;
    uint32_t left_length = 0, right_length = 0;
    int rc = name_view(image, left, &left_chars, &left_length, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;
    rc = name_view(image, right, &right_chars, &right_length, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;

    const uint32_t common = left_length < right_length ?
                            left_length : right_length;
    for (uint32_t i = 0; i < common; ++i) {
        const uint16_t left_unit = read_u16(left_chars + i * 2u);
        const uint16_t right_unit = read_u16(right_chars + i * 2u);
        if (left_unit != right_unit) {
            *comparison = left_unit < right_unit ? -1 : 1;
            return RESOURCE_SCAN_PRESENT;
        }
    }
    *comparison = left_length < right_length ? -1 :
                  left_length > right_length ? 1 : 0;
    return RESOURCE_SCAN_PRESENT;
}

static int validate_name(const GuestPEImage *image, uint32_t name,
                         uint32_t *fault)
{
    const uint8_t *characters = NULL;
    uint32_t length = 0;
    return name_view(image, name, &characters, &length, fault);
}

static int read_directory(const GuestPEImage *image, uint32_t offset,
                          ResourceDirectory *directory, uint32_t *fault)
{
    const uint8_t *header = NULL;
    int rc = resource_bytes(image, offset, RESOURCE_DIRECTORY_HEADER_SIZE,
                            &header, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;

    const uint32_t named = read_u16(header + 12u);
    const uint32_t ids = read_u16(header + 14u);
    const uint32_t count = named + ids;
    if (count > RESOURCE_ENTRY_LIMIT) return RESOURCE_SCAN_INVALID;

    const uint32_t table_size = RESOURCE_DIRECTORY_HEADER_SIZE +
                                count * RESOURCE_DIRECTORY_ENTRY_SIZE;
    const uint8_t *table = NULL;
    rc = resource_bytes(image, offset, table_size, &table, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;

    directory->bytes = table + RESOURCE_DIRECTORY_HEADER_SIZE;
    directory->offset = offset;
    directory->named_count = named;
    directory->id_count = ids;
    directory->entry_count = count;
    return RESOURCE_SCAN_PRESENT;
}

static int validate_subdirectory(const GuestPEImage *image, uint32_t target,
                                 uint32_t *fault)
{
    ResourceDirectory ignored;
    return read_directory(image, target, &ignored, fault);
}

static int entries_have_valid_names_and_subdirectories(
    const GuestPEImage *image, const ResourceDirectory *directory,
    int has_ancestor, uint32_t ancestor_offset, uint32_t *fault)
{
    uint32_t previous_id = 0;
    for (uint32_t i = 0; i < directory->entry_count; ++i) {
        const uint8_t *entry = directory->bytes +
                               i * RESOURCE_DIRECTORY_ENTRY_SIZE;
        const uint32_t name = read_u32(entry);
        const uint32_t target = read_u32(entry + 4u);
        const int has_name_string =
            (name & UINT32_C(0x80000000)) != 0u;
        if ((i < directory->named_count) != has_name_string) {
            return RESOURCE_SCAN_INVALID;
        }
        int rc = validate_name(image, name, fault);
        if (rc != RESOURCE_SCAN_PRESENT) return rc;

        if (i < directory->named_count && i > 0u) {
            const uint8_t *previous = directory->bytes +
                (i - 1u) * RESOURCE_DIRECTORY_ENTRY_SIZE;
            int comparison = 0;
            rc = compare_named_entries(image, read_u32(previous), name,
                                       &comparison, fault);
            if (rc != RESOURCE_SCAN_PRESENT) return rc;
            if (comparison >= 0) return RESOURCE_SCAN_INVALID;
        } else if (i >= directory->named_count) {
            const uint32_t id = name;
            if (i != directory->named_count && id <= previous_id) {
                return RESOURCE_SCAN_INVALID;
            }
            previous_id = id;
        }

        if (!(target & UINT32_C(0x80000000))) {
            return RESOURCE_SCAN_INVALID;
        }
        const uint32_t child_offset = target & UINT32_C(0x7fffffff);
        if (child_offset == directory->offset ||
            (has_ancestor && child_offset == ancestor_offset)) {
            return RESOURCE_SCAN_INVALID;
        }
        rc = validate_subdirectory(image, child_offset, fault);
        if (rc != RESOURCE_SCAN_PRESENT) return rc;
    }
    return RESOURCE_SCAN_PRESENT;
}

static int scan_resource_directory(const GuestPEImage *image, uint32_t *fault)
{
    if (!resource_span_valid(image)) return RESOURCE_SCAN_INVALID;
    if (!image->resource_address) return RESOURCE_SCAN_ABSENT;

    ResourceDirectory root;
    int rc = read_directory(image, 0u, &root, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;
    rc = entries_have_valid_names_and_subdirectories(image, &root, 0,
                                                      0u, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;

    uint32_t group_type_offset = 0;
    unsigned group_type_count = 0;
    for (uint32_t i = root.named_count; i < root.entry_count; ++i) {
        const uint8_t *entry = root.bytes + i * RESOURCE_DIRECTORY_ENTRY_SIZE;
        if (read_u32(entry) == RT_GROUP_ICON) {
            group_type_offset = read_u32(entry + 4u) &
                                UINT32_C(0x7fffffff);
            ++group_type_count;
        }
    }
    if (group_type_count == 0u) return RESOURCE_SCAN_ABSENT;
    if (group_type_count != 1u) return RESOURCE_SCAN_INVALID;

    ResourceDirectory group_types;
    rc = read_directory(image, group_type_offset, &group_types, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;
    rc = entries_have_valid_names_and_subdirectories(
        image, &group_types, 1, root.offset, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;

    uint32_t application_icon_offset = 0;
    unsigned application_icon_count = 0;
    for (uint32_t i = group_types.named_count;
         i < group_types.entry_count; ++i) {
        const uint8_t *entry = group_types.bytes +
                               i * RESOURCE_DIRECTORY_ENTRY_SIZE;
        if (read_u32(entry) == LOADICONA_IDI_APPLICATION) {
            application_icon_offset = read_u32(entry + 4u) &
                                      UINT32_C(0x7fffffff);
            ++application_icon_count;
        }
    }
    if (application_icon_count == 0u) return RESOURCE_SCAN_ABSENT;
    if (application_icon_count != 1u) return RESOURCE_SCAN_INVALID;

    ResourceDirectory languages;
    rc = read_directory(image, application_icon_offset, &languages, fault);
    if (rc != RESOURCE_SCAN_PRESENT) return rc;
    if (languages.entry_count == 0u) return RESOURCE_SCAN_INVALID;

    uint32_t previous_id = 0;
    for (uint32_t i = 0; i < languages.entry_count; ++i) {
        const uint8_t *entry = languages.bytes +
                               i * RESOURCE_DIRECTORY_ENTRY_SIZE;
        const uint32_t name = read_u32(entry);
        const uint32_t data_offset = read_u32(entry + 4u);
        const int has_name_string =
            (name & UINT32_C(0x80000000)) != 0u;
        if ((i < languages.named_count) != has_name_string) {
            return RESOURCE_SCAN_INVALID;
        }
        rc = validate_name(image, name, fault);
        if (rc != RESOURCE_SCAN_PRESENT) return rc;
        if (data_offset & UINT32_C(0x80000000)) {
            return RESOURCE_SCAN_INVALID;
        }
        if (i < languages.named_count && i > 0u) {
            const uint8_t *previous = languages.bytes +
                (i - 1u) * RESOURCE_DIRECTORY_ENTRY_SIZE;
            int comparison = 0;
            rc = compare_named_entries(image, read_u32(previous), name,
                                       &comparison, fault);
            if (rc != RESOURCE_SCAN_PRESENT) return rc;
            if (comparison >= 0) return RESOURCE_SCAN_INVALID;
        } else if (i >= languages.named_count) {
            if (i != languages.named_count && name <= previous_id) {
                return RESOURCE_SCAN_INVALID;
            }
            previous_id = name;
        }

        const uint8_t *data_entry = NULL;
        rc = resource_bytes(image, data_offset, RESOURCE_DATA_ENTRY_SIZE,
                            &data_entry, fault);
        if (rc != RESOURCE_SCAN_PRESENT) return rc;
        const uint32_t data_rva = read_u32(data_entry);
        const uint32_t data_size = read_u32(data_entry + 4u);
        if ((uint64_t)data_rva + data_size > image->image_size) {
            return RESOURCE_SCAN_INVALID;
        }
    }
    return RESOURCE_SCAN_PRESENT;
}

static int write_guest_last_error(CPU *cpu, uint32_t value, uint32_t *fault)
{
    if (!cpu->fs_base) {
        *fault = 0u;
        return -2;
    }
    const uint64_t address = (uint64_t)cpu->fs_base + 0x34u;
    if (address > UINT32_MAX || address + sizeof(value) > GUEST_MEMORY_SIZE) {
        *fault = address > UINT32_MAX ? UINT32_MAX : (uint32_t)address;
        return -1;
    }
    void *pointer = guest_memory_pointer((uint32_t)address, sizeof(value), 1);
    if (!pointer) {
        *fault = (uint32_t)address;
        return -1;
    }
    memcpy(pointer, &value, sizeof(value));
    return 0;
}

int guest_resources_import(CPU *cpu, const GuestImport *import,
                           const GuestPEImage *image, uint32_t *fault)
{
    if (!cpu || !import || !fault || !import->library || !import->name) {
        return 0;
    }
    if (strcasecmp(import->library, "USER32.dll") != 0 ||
        strcmp(import->name, "LoadIconA") != 0) {
        return 0;
    }
    if (!image) return 0;

    const uint8_t *frame_bytes = (const uint8_t *)guest_memory_pointer(
        cpu->esp, LOADICONA_FRAME_SIZE, 0);
    if (!frame_bytes) {
        *fault = cpu->esp;
        return -1;
    }
    uint32_t frame[3];
    memcpy(frame, frame_bytes, sizeof(frame));
    const uint32_t return_ip = frame[0];
    const uint32_t module = frame[1];
    const uint32_t resource_id = frame[2];

    if (module != image->image_base ||
        resource_id != LOADICONA_IDI_APPLICATION) {
        return 0;
    }

    const int scan_result = scan_resource_directory(image, fault);
    if (scan_result == RESOURCE_SCAN_FAULT) return -1;
    if (scan_result != RESOURCE_SCAN_ABSENT) return 0;

    const int error_result = write_guest_last_error(
        cpu, ERROR_RESOURCE_TYPE_NOT_FOUND, fault);
    if (error_result != 0) return error_result;

    cpu->eax = 0u;
    cpu->eip = return_ip;
    cpu->esp += LOADICONA_FRAME_SIZE;
    return 1;
}
