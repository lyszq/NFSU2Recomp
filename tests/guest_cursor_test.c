/*
 * Unit tests for guest_cursor (coordinate scaling, thread-safe atomics, Win32 USER32 cursor imports)
 */

#include "guest_cursor.h"
#include "guest_memory.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
}

static void test_viewport_scaling(void) {
    guest_cursor_reset();

    /* 1:1 scaling */
    guest_cursor_set_viewport(1280, 720, 1280, 720, GUEST_CURSOR_SCALE_FIT);
    int32_t gx = 0, gy = 0;
    guest_cursor_host_to_game(640.0f, 360.0f, &gx, &gy);
    assert(gx == 640 && gy == 360);

    /* 1920x1080 viewport with 640x480 (4:3) game:
     * scale = min(1920/640, 1080/480) = min(3.0, 2.25) = 2.25
     * pillarbox margins: gw*scale = 640*2.25 = 1440. offset_x = (1920 - 1440) / 2 = 240.
     * offset_y = 0.
     */
    guest_cursor_set_viewport(1920, 1080, 640, 480, GUEST_CURSOR_SCALE_FIT);
    guest_cursor_host_to_game(240.0f, 0.0f, &gx, &gy);
    assert(gx == 0 && gy == 0);

    guest_cursor_host_to_game(960.0f, 540.0f, &gx, &gy);
    assert(gx == 320 && gy == 240);

    /* Out of bounds clamping */
    guest_cursor_host_to_game(50.0f, 540.0f, &gx, &gy);
    assert(gx == 0); /* Left black bar clamps to 0 */

    guest_cursor_host_to_game(1900.0f, 540.0f, &gx, &gy);
    assert(gx == 639); /* Right black bar clamps to 639 */

    printf("PASS: test_viewport_scaling\n");
}

static void test_host_ingress_and_synthetic(void) {
    guest_cursor_reset();
    guest_cursor_set_viewport(1280, 720, 1280, 720, GUEST_CURSOR_SCALE_FIT);

    guest_cursor_set_host_pos(100.0f, 200.0f, true);
    GuestCursorCoords coords = guest_cursor_get_coords();
    assert(coords.x == 100 && coords.y == 200);
    assert(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_DOWN);
    assert(guest_cursor_get_flags() & GUEST_CURSOR_FLAG_AVAILABLE);

    /* Synthetic injection override */
    guest_cursor_inject_synthetic(999, 888, GUEST_CURSOR_FLAG_AVAILABLE);
    assert(guest_cursor_is_synthetic());
    coords = guest_cursor_get_coords();
    assert(coords.x == 999 && coords.y == 888);

    /* Host ingress must be suppressed while synthetic is active */
    guest_cursor_set_host_pos(50.0f, 50.0f, false);
    coords = guest_cursor_get_coords();
    assert(coords.x == 999 && coords.y == 888);

    /* Clear synthetic */
    guest_cursor_clear_synthetic();
    assert(!guest_cursor_is_synthetic());
    guest_cursor_set_host_pos(300.0f, 400.0f, false);
    coords = guest_cursor_get_coords();
    assert(coords.x == 300 && coords.y == 400);

    printf("PASS: test_host_ingress_and_synthetic\n");
}

static void test_win32_get_cursor_pos_success(void) {
    guest_cursor_reset();
    guest_cursor_inject_synthetic(500, 300, GUEST_CURSOR_FLAG_AVAILABLE);

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CPU before = cpu;

    /* Push args on stack: return_ip (0x1234), lpPoint (POINT_ADDR) */
    uint8_t *stk = guest_memory_pointer(STACK_ADDR, 8, 1);
    assert(stk != NULL);
    memcpy(stk, "\x34\x12\x00\x00", 4);
    uint32_t pt_addr = POINT_ADDR;
    memcpy(stk + 4, &pt_addr, 4);

    /* Fill POINT_ADDR with canary */
    uint8_t *pt = guest_memory_pointer(POINT_ADDR, 8, 1);
    assert(pt != NULL);
    memset(pt, 0xAA, 8);

    GuestImport imp = { .iat = 0, .library = "USER32.dll", .name = "GetCursorPos" };
    uint32_t fault = 0;
    int rc = guest_user32_get_cursor_pos(&cpu, &imp, &fault);
    assert(rc == 1);
    assert(cpu.eax == 1); /* TRUE */
    assert(cpu.eip == 0x00001234u);
    assert(cpu.esp == STACK_ADDR + 8u); /* Callee cleaned 4 bytes + ret 4 = 8 */

    /* Callee-saved registers intact */
    assert(cpu.ebx == before.ebx);
    assert(cpu.esi == before.esi);
    assert(cpu.edi == before.edi);
    assert(cpu.ebp == before.ebp);

    /* Verify coordinates written to point */
    int32_t rx = 0, ry = 0;
    memcpy(&rx, pt, 4);
    memcpy(&ry, pt + 4, 4);
    assert(rx == 500 && ry == 300);

    printf("PASS: test_win32_get_cursor_pos_success\n");
}

static void test_win32_get_cursor_pos_null(void) {
    guest_cursor_reset();

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    CPU before = cpu;

    /* Push args: return_ip (0x1234), lpPoint = NULL (0) */
    uint8_t *stk = guest_memory_pointer(STACK_ADDR, 8, 1);
    assert(stk != NULL);
    memcpy(stk, "\x34\x12\x00\x00", 4);
    memset(stk + 4, 0, 4);

    GuestImport imp = { .iat = 0, .library = "USER32.dll", .name = "GetCursorPos" };
    uint32_t fault = 0;
    int rc = guest_user32_get_cursor_pos(&cpu, &imp, &fault);
    assert(rc == 1);
    assert(cpu.eax == 0); /* FALSE */
    assert(cpu.eip == 0x00001234u);
    assert(cpu.esp == STACK_ADDR + 8u);
    assert(cpu.ebx == before.ebx);

    /* Verify LastError set to 998 (ERROR_NOACCESS) at TEB+0x34 */
    uint8_t *teb = guest_memory_pointer(TEB_ADDR + 0x34u, 4, 0);
    assert(teb != NULL);
    uint32_t err = 0;
    memcpy(&err, teb, 4);
    assert(err == 998u);

    printf("PASS: test_win32_get_cursor_pos_null\n");
}

static void test_win32_set_and_show_cursor(void) {
    guest_cursor_reset();

    CPU cpu;
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);

    /* SetCursorPos(150, 250) */
    uint8_t *stk = guest_memory_pointer(STACK_ADDR, 12, 1);
    assert(stk != NULL);
    memcpy(stk, "\x56\x34\x00\x00", 4); /* ret */
    int32_t x = 150, y = 250;
    memcpy(stk + 4, &x, 4);
    memcpy(stk + 8, &y, 4);

    GuestImport imp_set = { .iat = 0, .library = "USER32.dll", .name = "SetCursorPos" };
    uint32_t fault = 0;
    int rc = guest_user32_set_cursor_pos(&cpu, &imp_set, &fault);
    assert(rc == 1);
    assert(cpu.eax == 1);
    assert(cpu.esp == STACK_ADDR + 12u);
    GuestCursorCoords c = guest_cursor_get_coords();
    assert(c.x == 150 && c.y == 250);

    /* ShowCursor(TRUE) */
    stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    memcpy(stk, "\x78\x56\x00\x00", 4);
    uint32_t bshow = 1;
    memcpy(stk + 4, &bshow, 4);

    GuestImport imp_show = { .iat = 0, .library = "USER32.dll", .name = "ShowCursor" };
    rc = guest_user32_show_cursor(&cpu, &imp_show, &fault);
    assert(rc == 1);
    assert((int32_t)cpu.eax == 1); /* Count incremented from 0 to 1 */

    /* ShowCursor(FALSE) */
    stk = guest_memory_pointer(cpu.esp, 8, 1);
    assert(stk != NULL);
    memcpy(stk, "\x90\x78\x00\x00", 4);
    bshow = 0;
    memcpy(stk + 4, &bshow, 4);
    rc = guest_user32_show_cursor(&cpu, &imp_show, &fault);
    assert(rc == 1);
    assert((int32_t)cpu.eax == 0); /* Count decremented to 0 */

    printf("PASS: test_win32_set_and_show_cursor\n");
}

int main(void) {
    printf("=== Running guest_cursor Native Tests ===\n");
    int rc = guest_memory_init();
    assert(rc == 0);

    rc = guest_memory_commit(STACK_ADDR, 0x10000u);
    assert(rc == 0);
    rc = guest_memory_commit(TEB_ADDR, 0x10000u);
    assert(rc == 0);
    rc = guest_memory_commit(POINT_ADDR, 0x10000u);
    assert(rc == 0);

    test_viewport_scaling();
    test_host_ingress_and_synthetic();
    test_win32_get_cursor_pos_success();
    test_win32_get_cursor_pos_null();
    test_win32_set_and_show_cursor();

    guest_memory_shutdown();
    printf("=== All guest_cursor Native Tests PASSED ===\n");
    return 0;
}
