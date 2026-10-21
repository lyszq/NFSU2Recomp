/* Native regression tests for coherent live cursor state and explicit fixtures. */

#include "guest_cursor.h"
#include "guest_memory.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define STACK_ADDR 0x00100000u
#define TEB_ADDR   0x00200000u
#define POINT_ADDR 0x00300000u

static void init_cpu(CPU *c, uint32_t esp, uint32_t fs_base) {
    memset(c, 0, sizeof(*c));
    c->eax = 0x11111111u;
    c->ebx = 0x22222222u;
    c->ecx = 0x33333333u;
    c->edx = 0x44444444u;
    c->esi = 0x55555555u;
    c->edi = 0x66666666u;
    c->ebp = 0x77777777u;
    c->esp = esp;
    c->eip = 0x88888888u;
    c->fs_base = fs_base;
    eflags_set(c, 0x246u);
    for (int i = 0; i < 8; i++) c->st[i] = (double)(i + 1) * 1.25;
    c->top = 3;
    c->fcw = 0x037fu;
    c->fsw = 0x1200u;
    for (int i = 0; i < 8; i++) c->mm[i] = UINT64_C(0x0102030405060708) + (uint64_t)i;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 16; j++) c->xmm[i].b[j] = (uint8_t)(i * 16 + j);
    }
}

static void write_get_frame(uint32_t ret_ip, uint32_t point) {
    uint8_t *stk = guest_memory_pointer(STACK_ADDR, 8, 1);
    assert(stk != NULL);
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &point, 4);
}

static void write_set_frame(uint32_t ret_ip, int32_t x, int32_t y) {
    uint8_t *stk = guest_memory_pointer(STACK_ADDR, 12, 1);
    assert(stk != NULL);
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &x, 4);
    memcpy(stk + 8, &y, 4);
}

static int32_t read_i32(const void *p) {
    int32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void test_initial_state_and_viewport(void) {
    guest_cursor_reset();
    GuestCursorSnapshot snapshot = guest_cursor_get_snapshot();
    assert(!(snapshot.flags & GUEST_CURSOR_FLAG_AVAILABLE));
    assert(!snapshot.position_valid);
    assert(snapshot.flags & GUEST_CURSOR_FLAG_VISIBLE);

    int32_t gx = -1;
    int32_t gy = -1;
    guest_cursor_set_viewport(1280, 720, 1280, 720, GUEST_CURSOR_SCALE_FIT);
    guest_cursor_host_to_game(640.0f, 360.0f, &gx, &gy);
    assert(gx == 640 && gy == 360);

    guest_cursor_set_viewport(1920, 1080, 640, 480, GUEST_CURSOR_SCALE_FIT);
    guest_cursor_host_to_game(240.0f, 0.0f, &gx, &gy);
    assert(gx == 0 && gy == 0);
    guest_cursor_host_to_game(960.0f, 540.0f, &gx, &gy);
    assert(gx == 320 && gy == 240);
    guest_cursor_host_to_game(50.0f, 540.0f, &gx, &gy);
    assert(gx == 0);
    guest_cursor_host_to_game(1900.0f, 540.0f, &gx, &gy);
    assert(gx == 639);

    float hx = 0.0f;
    float hy = 0.0f;
    guest_cursor_game_to_host(320, 240, &hx, &hy);
    assert(hx == 960.0f && hy == 540.0f);

    /* Invalid dimensions do not partially replace the current viewport. */
    guest_cursor_set_viewport(0, 10, 20, 30, GUEST_CURSOR_SCALE_STRETCH);
    guest_cursor_host_to_game(960.0f, 540.0f, &gx, &gy);
    assert(gx == 320 && gy == 240);
    printf("PASS: test_initial_state_and_viewport\n");
}

static GuestCursorSnapshot g_worker_snapshot;

static void *read_live_snapshot(void *unused) {
    (void)unused;
    g_worker_snapshot = guest_cursor_get_snapshot();
    return NULL;
}

static void test_live_and_thread_local_synthetic_snapshot(void) {
    guest_cursor_reset();
    guest_cursor_set_viewport(1280, 720, 1280, 720, GUEST_CURSOR_SCALE_FIT);
    guest_cursor_set_host_pos(100.0f, 200.0f, true);

    GuestCursorSnapshot live = guest_cursor_get_snapshot();
    assert(live.position_valid);
    assert(live.flags & GUEST_CURSOR_FLAG_AVAILABLE);
    assert(live.flags & GUEST_CURSOR_FLAG_DOWN);
    assert(live.coords.x == 100 && live.coords.y == 200);

    const uint32_t fixture_flags = GUEST_CURSOR_FLAG_AVAILABLE | GUEST_CURSOR_FLAG_VISIBLE;
    guest_cursor_inject_synthetic(999, 888, fixture_flags);
    assert(guest_cursor_is_synthetic());
    GuestCursorSnapshot fixture = guest_cursor_get_snapshot();
    assert(fixture.position_valid);
    assert(fixture.coords.x == 999 && fixture.coords.y == 888);
    assert(fixture.flags == fixture_flags); /* No synthetic or live bits are added. */

    /* The fixture belongs only to the injecting thread. */
    pthread_t reader;
    assert(pthread_create(&reader, NULL, read_live_snapshot, NULL) == 0);
    assert(pthread_join(reader, NULL) == 0);
    assert(g_worker_snapshot.position_valid);
    assert(g_worker_snapshot.coords.x == 100 && g_worker_snapshot.coords.y == 200);
    assert(g_worker_snapshot.flags & GUEST_CURSOR_FLAG_DOWN);

    /* UI ingress remains live while this thread sees the fixture override. */
    guest_cursor_set_host_pos(50.0f, 50.0f, false);
    fixture = guest_cursor_get_snapshot();
    assert(fixture.coords.x == 999 && fixture.coords.y == 888);
    assert(fixture.flags == fixture_flags);

    guest_cursor_clear_synthetic();
    assert(!guest_cursor_is_synthetic());
    live = guest_cursor_get_snapshot();
    assert(live.position_valid);
    assert(live.coords.x == 50 && live.coords.y == 50);
    assert(live.flags & GUEST_CURSOR_FLAG_AVAILABLE);
    assert(!(live.flags & GUEST_CURSOR_FLAG_DOWN));

    guest_cursor_set_available(false);
    live = guest_cursor_get_snapshot();
    assert(!(live.flags & GUEST_CURSOR_FLAG_AVAILABLE));
    assert(!(live.flags & GUEST_CURSOR_FLAG_DOWN));
    assert(!live.position_valid);
    printf("PASS: test_live_and_thread_local_synthetic_snapshot\n");
}

static void test_get_cursor_pos_unavailable_is_unsupported(void) {
    guest_cursor_reset();
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_get_frame(0x1234u, POINT_ADDR);
    uint8_t *point = guest_memory_pointer(POINT_ADDR, 8, 1);
    assert(point != NULL);
    memset(point, 0xA5, 8);

    GuestImport import = { .iat = 0, .library = "USER32.dll", .name = "GetCursorPos" };
    uint32_t fault = 0xDEADBEEFu;
    CPU before = cpu;
    uint8_t point_before[8];
    memcpy(point_before, point, sizeof(point_before));
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 0);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(memcmp(point, point_before, sizeof(point_before)) == 0);
    assert(fault == 0xDEADBEEFu);

    /* Availability alone does not invent a coordinate. */
    guest_cursor_set_available(true);
    before = cpu;
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 0);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(memcmp(point, point_before, sizeof(point_before)) == 0);
    assert(fault == 0xDEADBEEFu);
    printf("PASS: test_get_cursor_pos_unavailable_is_unsupported\n");
}

static void test_get_cursor_pos_live_and_fixture(void) {
    guest_cursor_reset();
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_get_frame(0x1234u, POINT_ADDR);
    uint8_t *point = guest_memory_pointer(POINT_ADDR, 8, 1);
    assert(point != NULL);
    memset(point, 0xAA, 8);
    GuestImport import = { .iat = 0, .library = "USER32.dll", .name = "GetCursorPos" };
    uint32_t fault = 0;

    guest_cursor_set_host_pos(500.0f, 300.0f, false);
    CPU before = cpu;
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 1);
    CPU expected = before;
    expected.eax = 1;
    expected.eip = 0x1234u;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(read_i32(point) == 500 && read_i32(point + 4) == 300);

    guest_cursor_inject_synthetic(321, 123, GUEST_CURSOR_FLAG_AVAILABLE);
    write_get_frame(0x5678u, POINT_ADDR);
    memset(point, 0xCC, 8);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 1);
    expected = before;
    expected.eax = 1;
    expected.eip = 0x5678u;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(read_i32(point) == 321 && read_i32(point + 4) == 123);

    guest_cursor_clear_synthetic();
    write_get_frame(0x9ABCu, POINT_ADDR);
    memset(point, 0xDD, 8);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 1);
    expected = before;
    expected.eax = 1;
    expected.eip = 0x9ABCu;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(read_i32(point) == 500 && read_i32(point + 4) == 300);
    printf("PASS: test_get_cursor_pos_live_and_fixture\n");
}

static void test_get_cursor_pos_null_pointer(void) {
    guest_cursor_reset();
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_get_frame(0x1234u, 0);

    GuestImport import = { .iat = 0, .library = "USER32.dll", .name = "GetCursorPos" };
    uint32_t fault = 0;
    CPU before = cpu;
    assert(guest_user32_get_cursor_pos(&cpu, &import, &fault) == 1);
    CPU expected = before;
    expected.eax = 0;
    expected.eip = 0x1234u;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);

    const uint8_t *teb = guest_memory_pointer(TEB_ADDR + 0x34u, 4, 0);
    assert(teb != NULL);
    uint32_t error_code = 0;
    memcpy(&error_code, teb, 4);
    assert(error_code == 998u);
    printf("PASS: test_get_cursor_pos_null_pointer\n");
}

static void test_set_and_show_cursor(void) {
    guest_cursor_reset();
    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    GuestImport set_import = { .iat = 0, .library = "USER32.dll", .name = "SetCursorPos" };
    uint32_t fault = 0xF00DF00Du;
    write_set_frame(0x3456u, 150, 250);

    CPU before = cpu;
    assert(guest_user32_set_cursor_pos(&cpu, &set_import, &fault) == 0);
    assert(memcmp(&cpu, &before, sizeof(cpu)) == 0);
    assert(fault == 0xF00DF00Du);
    assert(!guest_cursor_get_snapshot().position_valid);

    /* An explicit available fixture can satisfy the call without touching live state. */
    guest_cursor_inject_synthetic(7, 9, GUEST_CURSOR_FLAG_AVAILABLE);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_set_frame(0x4567u, 30, 40);
    before = cpu;
    assert(guest_user32_set_cursor_pos(&cpu, &set_import, &fault) == 1);
    CPU expected = before;
    expected.eax = 1;
    expected.eip = 0x4567u;
    expected.esp += 12u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    GuestCursorSnapshot fixture = guest_cursor_get_snapshot();
    assert(fixture.coords.x == 30 && fixture.coords.y == 40);
    guest_cursor_clear_synthetic();
    assert(!guest_cursor_get_snapshot().position_valid);

    /* A real host position establishes live availability before SetCursorPos. */
    guest_cursor_set_host_pos(10.0f, 20.0f, false);
    write_set_frame(0x3456u, 150, 250);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    before = cpu;
    assert(guest_user32_set_cursor_pos(&cpu, &set_import, &fault) == 1);
    expected = before;
    expected.eax = 1;
    expected.eip = 0x3456u;
    expected.esp += 12u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    GuestCursorSnapshot snapshot = guest_cursor_get_snapshot();
    assert(snapshot.position_valid && (snapshot.flags & GUEST_CURSOR_FLAG_AVAILABLE));
    assert(snapshot.coords.x == 150 && snapshot.coords.y == 250);

    GuestImport show_import = { .iat = 0, .library = "USER32.dll", .name = "ShowCursor" };
    uint8_t *stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    uint32_t ret_ip = 0x5678u;
    uint32_t show = 1;
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &show, 4);
    before = cpu;
    assert(guest_user32_show_cursor(&cpu, &show_import, &fault) == 1);
    expected = before;
    expected.eax = 1;
    expected.eip = ret_ip;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_VISIBLE);

    stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    ret_ip = 0x789Au;
    show = 0;
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &show, 4);
    before = cpu;
    assert(guest_user32_show_cursor(&cpu, &show_import, &fault) == 1);
    expected = before;
    expected.eax = 0;
    expected.eip = ret_ip;
    expected.esp += 8u;
    assert(memcmp(&cpu, &expected, sizeof(cpu)) == 0);
    assert(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_VISIBLE);
    assert(guest_cursor_get_display_count() == 0);

    /* ShowCursor inside a fixture must not alter the live display state. */
    GuestCursorSnapshot live_before_fixture = guest_cursor_get_snapshot();
    guest_cursor_inject_synthetic(320, 180, GUEST_CURSOR_FLAG_AVAILABLE);
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    ret_ip = 0x1357u;
    show = 0;
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &show, 4);
    assert(guest_user32_show_cursor(&cpu, &show_import, &fault) == 1);
    assert((int32_t)cpu.eax == -1);
    assert(guest_cursor_get_display_count() == -1);
    assert(!(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_VISIBLE));

    stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    ret_ip = 0x2468u;
    show = 1;
    memcpy(stk, &ret_ip, 4);
    memcpy(stk + 4, &show, 4);
    assert(guest_user32_show_cursor(&cpu, &show_import, &fault) == 1);
    assert((int32_t)cpu.eax == 0);
    assert(guest_cursor_get_display_count() == 0);
    assert(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_VISIBLE);
    guest_cursor_clear_synthetic();
    GuestCursorSnapshot live_after_fixture = guest_cursor_get_snapshot();
    assert(live_after_fixture.flags == live_before_fixture.flags);
    assert(live_after_fixture.position_valid == live_before_fixture.position_valid);
    assert(guest_cursor_get_display_count() == 0);
    printf("PASS: test_set_and_show_cursor\n");
}

static void test_mouse_state_sizes_and_guards(void) {
    guest_cursor_reset();
    guest_cursor_set_viewport(1280, 720, 1280, 720, GUEST_CURSOR_SCALE_FIT);

    unsigned char buffer[24];
    guest_cursor_set_host_pos(100.0f, 100.0f, false);
    guest_cursor_set_host_pos(125.0f, 140.0f, true);
    memset(buffer, 0xA5, sizeof(buffer));
    unsigned char canary[24];
    memcpy(canary, buffer, sizeof(canary));
    metal_fill_mouse(buffer, 15);
    assert(memcmp(buffer, canary, sizeof(buffer)) == 0);
    metal_fill_mouse(buffer, 17);
    assert(memcmp(buffer, canary, sizeof(buffer)) == 0);
    metal_fill_mouse(buffer, 19);
    assert(memcmp(buffer, canary, sizeof(buffer)) == 0);

    metal_fill_mouse(buffer, 16);
    assert(read_i32(buffer) == 25);
    assert(read_i32(buffer + 4) == 40);
    assert(read_i32(buffer + 8) == 0);
    assert(buffer[12] == 0x80);
    assert(buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 0);
    assert(buffer[16] == 0xA5 && buffer[23] == 0xA5); /* exact 16-byte write */

    /* The previous short calls did not consume this relative movement. */
    guest_cursor_set_host_pos(135.0f, 150.0f, true);
    guest_cursor_set_host_pos(130.0f, 160.0f, true);
    memset(buffer, 0xA5, sizeof(buffer));
    metal_fill_mouse(buffer, 20);
    assert(read_i32(buffer) == 5);
    assert(read_i32(buffer + 4) == 20);
    assert(read_i32(buffer + 8) == 0);
    assert(buffer[12] == 0x80);
    for (int i = 13; i < 20; i++) assert(buffer[i] == 0);
    assert(buffer[20] == 0xA5 && buffer[23] == 0xA5); /* trailing guard */

    /* Fixture mouse reads use isolated deltas and preserve pending live motion. */
    guest_cursor_set_host_pos(150.0f, 170.0f, true); /* Live delta +20,+10. */
    guest_cursor_inject_synthetic(320, 180,
        GUEST_CURSOR_FLAG_AVAILABLE | GUEST_CURSOR_FLAG_DOWN | GUEST_CURSOR_FLAG_VISIBLE);
    metal_mouse_add(3, -4); /* Synthetic deltas are local to this fixture/thread. */
    memset(buffer, 0xA5, sizeof(buffer));
    metal_fill_mouse(buffer, 20);
    assert(read_i32(buffer) == 3 && read_i32(buffer + 4) == -4);
    assert(buffer[12] == 0x80);
    guest_cursor_clear_synthetic();
    memset(buffer, 0xA5, sizeof(buffer));
    metal_fill_mouse(buffer, 20);
    assert(read_i32(buffer) == 20 && read_i32(buffer + 4) == 10);
    assert(buffer[12] == 0x80);

    guest_cursor_set_available(false);
    memset(buffer, 0xA5, sizeof(buffer));
    metal_fill_mouse(buffer, 20);
    assert(buffer[12] == 0); /* cancellation releases button 0 */
    assert(buffer[13] == 0 && buffer[19] == 0);

    metal_mouse_add(12, -8);
    memset(buffer, 0xA5, sizeof(buffer));
    metal_fill_mouse(buffer, 24);
    assert(read_i32(buffer) == 12 && read_i32(buffer + 4) == -8);
    assert(buffer[20] == 0xA5 && buffer[23] == 0xA5);
    printf("PASS: test_mouse_state_sizes_and_guards\n");
}

int main(void) {
    printf("=== Running guest_cursor Native Tests ===\n");
    assert(guest_memory_init() == 0);
    assert(guest_memory_commit(STACK_ADDR, 0x10000u) == 0);
    assert(guest_memory_commit(TEB_ADDR, 0x10000u) == 0);
    assert(guest_memory_commit(POINT_ADDR, 0x10000u) == 0);

    test_initial_state_and_viewport();
    test_live_and_thread_local_synthetic_snapshot();
    test_get_cursor_pos_unavailable_is_unsupported();
    test_get_cursor_pos_live_and_fixture();
    test_get_cursor_pos_null_pointer();
    test_set_and_show_cursor();
    test_mouse_state_sizes_and_guards();

    assert(guest_memory_shutdown() == 0);
    printf("=== All guest_cursor Native Tests PASSED ===\n");
    return 0;
}
