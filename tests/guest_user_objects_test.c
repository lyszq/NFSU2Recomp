#include "guest_user_objects.h"

#include "guest_memory.h"

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
    STACK_FAULT_ADDR = 0x00030000u,
    TEB_ADDR = 0x00020000u,
    LAST_ERROR_OFFSET = 0x34u,
    RETURN_ADDR = 0x00401234u,
    LAST_ERROR_SENTINEL = 0x13572468u
};

static void init_cpu(CPU *cpu, uint32_t stack)
{
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
    cpu->fs_base = TEB_ADDR;
    cpu->gs_base = 0x99999999u;
    cpu->cf = 1;
    cpu->pf = 0;
    cpu->af = 1;
    cpu->zf = 0;
    cpu->sf = 1;
    cpu->of = 0;
    cpu->df = 1;
}

static int write_bytes(uint32_t address, const void *source, size_t size)
{
    void *destination = guest_memory_pointer(address, size, 1);
    if (!destination) return 1;
    memcpy(destination, source, size);
    return 0;
}

static int write_u32(uint32_t address, uint32_t value)
{
    return write_bytes(address, &value, sizeof(value));
}

static int read_u32(uint32_t address, uint32_t *value)
{
    const void *source = guest_memory_pointer(address, sizeof(*value), 0);
    if (!source) return 1;
    memcpy(value, source, sizeof(*value));
    return 0;
}

static int write_frame(uint32_t stack, uint32_t return_ip, uint32_t module,
                       uint32_t cursor_name)
{
    const uint32_t frame[3] = { return_ip, module, cursor_name };
    return write_bytes(stack, frame, sizeof(frame));
}

static int test_measured_arrow(void)
{
    const uint32_t expected_handle = GUEST_USER_OBJECT_HANDLE_BASE + 1u;
    GuestImport api = { 0u, "uSeR32.dLl", "LoadCursorA" };
    GuestUserObjects objects = {0};
    GuestUserObjects other = {0};
    GuestUserObjects empty = {0};
    _Static_assert(sizeof empty == sizeof objects, "compare entire object tables");
    CPU cpu, before, expected;
    uint32_t fault = 0xabcdef01u;

    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    CHECK(!write_u32(TEB_ADDR + LAST_ERROR_OFFSET, LAST_ERROR_SENTINEL));
    init_cpu(&cpu, STACK_ADDR);
    before = cpu;

    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == 1);
    expected = before;
    expected.eax = expected_handle;
    expected.eip = RETURN_ADDR;
    expected.esp += 12u;
    CHECK(!memcmp(&cpu, &expected, sizeof(cpu)));
    CHECK(objects.count == 1u);
    CHECK(objects.entries[0].handle == expected_handle);
    CHECK(objects.entries[0].type == GUEST_USER_OBJECT_CURSOR);
    CHECK(objects.entries[0].source == GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED);
    CHECK(objects.entries[0].module == 0u);
    CHECK(objects.entries[0].resource_id == GUEST_USER_OBJECT_IDC_ARROW);
    CHECK(objects.entries[0].shared == 1u);
    CHECK(guest_user_objects_lookup(&objects, expected_handle,
                                    GUEST_USER_OBJECT_CURSOR) ==
          &objects.entries[0]);
    CHECK(!guest_user_objects_lookup(&objects, expected_handle,
                                     GUEST_USER_OBJECT_ICON));
    CHECK(!guest_user_objects_lookup(&other, expected_handle,
                                     GUEST_USER_OBJECT_CURSOR));
    CHECK(guest_user_objects_lookup(&objects, 0u,
                                    GUEST_USER_OBJECT_CURSOR) == NULL);
    CHECK(guest_user_objects_lookup(&objects, expected_handle,
                                    (GuestUserObjectType)99) == NULL);
    CHECK(objects.entries[0].handle != 0u);
    uint32_t last_error = 0;
    CHECK(!read_u32(TEB_ADDR + LAST_ERROR_OFFSET, &last_error));
    CHECK(last_error == LAST_ERROR_SENTINEL);

    /* The same shared resource returns the same table-backed handle. */
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR + 4u, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    init_cpu(&cpu, STACK_ADDR);
    before = cpu;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == 1);
    expected = before;
    expected.eax = expected_handle;
    expected.eip = RETURN_ADDR + 4u;
    expected.esp += 12u;
    CHECK(!memcmp(&cpu, &expected, sizeof(cpu)) && objects.count == 1u);

    guest_user_objects_cleanup(&objects);
    CHECK(!memcmp(&objects, &empty, sizeof(objects)));
    CHECK(!guest_user_objects_lookup(&objects, expected_handle,
                                     GUEST_USER_OBJECT_CURSOR));
    return 0;
}

static int test_unsupported_inputs_are_atomic(void)
{
    GuestImport api = { 0u, "USER32.dll", "LoadCursorA" };
    GuestUserObjects objects = {0};
    GuestUserObjects before_objects;
    CPU cpu, before_cpu;
    uint32_t fault = 0xabcdef01u;

    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW + 1u));
    before_cpu = cpu;
    before_objects = objects;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&objects, &before_objects, sizeof(objects)));
    CHECK(fault == 0xabcdef01u);

    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0x00400000u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    before_cpu = cpu;
    before_objects = objects;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&objects, &before_objects, sizeof(objects)));

    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u, 0x00028000u));
    before_cpu = cpu;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)) && !objects.count);

    GuestImport wrong_library = { 0u, "KERNEL32.dll", "LoadCursorA" };
    CHECK(guest_user_objects_import(&cpu, &wrong_library, &objects, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)) && !objects.count);
    GuestImport wrong_api = { 0u, "USER32.dll", "LoadIconA" };
    CHECK(guest_user_objects_import(&cpu, &wrong_api, &objects, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)) && !objects.count);

    /* Sparse tables allocate the first free slot while retaining the
     * slot-derived virtual handle identity. */
    GuestUserObjects sparse = {0};
    sparse.entries[0] = (GuestUserObject){
        .handle = GUEST_USER_OBJECT_HANDLE_BASE + 1u,
        .type = GUEST_USER_OBJECT_ICON,
        .source = GUEST_USER_OBJECT_SOURCE_PE_IMAGE,
        .module = 0x00400000u,
        .resource_id = 7u,
        .shared = 0u,
    };
    sparse.entries[2] = (GuestUserObject){
        .handle = GUEST_USER_OBJECT_HANDLE_BASE + 3u,
        .type = GUEST_USER_OBJECT_ICON,
        .source = GUEST_USER_OBJECT_SOURCE_PE_IMAGE,
        .module = 0x00400000u,
        .resource_id = 9u,
        .shared = 0u,
    };
    sparse.count = 2u;
    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    before_cpu = cpu;
    CHECK(guest_user_objects_import(&cpu, &api, &sparse, &fault) == 1);
    CHECK(cpu.eax == GUEST_USER_OBJECT_HANDLE_BASE + 2u);
    CHECK(cpu.eip == RETURN_ADDR && cpu.esp == before_cpu.esp + 12u);
    CHECK(sparse.count == 3u);
    CHECK(sparse.entries[1].handle == GUEST_USER_OBJECT_HANDLE_BASE + 2u);
    CHECK(sparse.entries[1].type == GUEST_USER_OBJECT_CURSOR);
    CHECK(sparse.entries[2].type == GUEST_USER_OBJECT_ICON);

    GuestUserObjects full = {0};
    for (uint32_t i = 0; i < GUEST_USER_OBJECT_LIMIT; ++i) {
        full.entries[i] = (GuestUserObject){
            .handle = GUEST_USER_OBJECT_HANDLE_BASE + i + 1u,
            .type = GUEST_USER_OBJECT_ICON,
            .source = GUEST_USER_OBJECT_SOURCE_PE_IMAGE,
            .module = 0x00400000u,
            .resource_id = i + 1u,
            .shared = 0u,
        };
    }
    full.count = GUEST_USER_OBJECT_LIMIT;
    GuestUserObjects full_before = full;
    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    before_cpu = cpu;
    CHECK(guest_user_objects_import(&cpu, &api, &full, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&full, &full_before, sizeof(full)));

    GuestUserObjects corrupt = {0};
    corrupt.entries[0] = (GuestUserObject){
        .handle = GUEST_USER_OBJECT_HANDLE_BASE + 2u,
        .type = GUEST_USER_OBJECT_CURSOR,
        .source = GUEST_USER_OBJECT_SOURCE_SYSTEM_SHARED,
        .module = 0u,
        .resource_id = GUEST_USER_OBJECT_IDC_ARROW,
        .shared = 1u,
    };
    corrupt.count = 1u;
    GuestUserObjects corrupt_before = corrupt;
    init_cpu(&cpu, STACK_ADDR);
    CHECK(!write_frame(STACK_ADDR, RETURN_ADDR, 0u,
                       GUEST_USER_OBJECT_IDC_ARROW));
    before_cpu = cpu;
    CHECK(guest_user_objects_import(&cpu, &api, &corrupt, &fault) == 0);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&corrupt, &corrupt_before, sizeof(corrupt)));
    CHECK(!guest_user_objects_lookup(&corrupt,
                                    GUEST_USER_OBJECT_HANDLE_BASE + 2u,
                                    GUEST_USER_OBJECT_CURSOR));

    CHECK(guest_user_objects_import(NULL, &api, &objects, &fault) == 0);
    CHECK(guest_user_objects_import(&cpu, NULL, &objects, &fault) == 0);
    CHECK(guest_user_objects_import(&cpu, &api, NULL, &fault) == 0);
    CHECK(guest_user_objects_import(&cpu, &api, &objects, NULL) == 0);
    return 0;
}

static int test_frame_fault_is_atomic(void)
{
    GuestImport api = { 0u, "USER32.dll", "LoadCursorA" };
    GuestUserObjects objects = {0};
    GuestUserObjects before_objects;
    CPU cpu, before_cpu;
    uint32_t fault = 0xabcdef01u;

    init_cpu(&cpu, STACK_FAULT_ADDR);
    before_cpu = cpu;
    before_objects = objects;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == -1);
    CHECK(fault == STACK_FAULT_ADDR);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&objects, &before_objects, sizeof(objects)));

    init_cpu(&cpu, 0xfffffff8u);
    before_cpu = cpu;
    fault = 0xabcdef01u;
    CHECK(guest_user_objects_import(&cpu, &api, &objects, &fault) == -1);
    CHECK(fault == 0xfffffff8u);
    CHECK(!memcmp(&cpu, &before_cpu, sizeof(cpu)));
    CHECK(!memcmp(&objects, &before_objects, sizeof(objects)));
    return 0;
}

int main(void)
{
    CHECK(!guest_memory_init());
    CHECK(!guest_memory_commit(STACK_ADDR, 0x4000u));
    CHECK(!guest_memory_commit(TEB_ADDR, 0x4000u));
    CHECK(!test_measured_arrow());
    CHECK(!test_unsupported_inputs_are_atomic());
    CHECK(!test_frame_fault_is_atomic());
    CHECK(!guest_memory_shutdown());
    puts("PASS | USER32 virtual resource objects | shared system IDC_ARROW descriptor + strict typed lookup + unsupported/fault atomicity");
    return 0;
}
