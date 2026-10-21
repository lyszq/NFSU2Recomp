/*
 * Test suite for NFSU2InputBridge (DirectInput DIK_* key table & analog mapping)
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ios/NFSU2iOS/Native/NFSU2InputBridge.h"
#include "guest_memory.h"

/* Guest memory emulation for standalone test runner */
uint8_t *g_mem = NULL;
uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];

static void test_initial_and_clear(void) {
    nfsu2_input_clear_all();
    assert(nfsu2_input_active_count() == 0);
    
    uint8_t kb[256];
    memset(kb, 0xFF, sizeof(kb));
    nfsu2_input_fill_keyboard(kb, 256);
    for (int i = 0; i < 256; i++) {
        assert(kb[i] == 0x00);
    }
    printf("PASS: test_initial_and_clear\n");
}

static void test_key_set_and_get(void) {
    nfsu2_input_clear_all();
    
    // Set gas and NOS
    nfsu2_input_set_key(NFSU2_DIK_UP, true);
    nfsu2_input_set_key(NFSU2_DIK_LSHIFT, true);
    
    assert(nfsu2_input_get_key(NFSU2_DIK_UP) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_LSHIFT) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_DOWN) == false);
    assert(nfsu2_input_active_count() == 2);
    
    uint8_t kb[256];
    nfsu2_input_fill_keyboard(kb, 256);
    assert(kb[NFSU2_DIK_UP] == 0x80);
    assert(kb[NFSU2_DIK_LSHIFT] == 0x80);
    assert(kb[NFSU2_DIK_DOWN] == 0x00);
    
    // Release NOS
    nfsu2_input_set_key(NFSU2_DIK_LSHIFT, false);
    assert(nfsu2_input_get_key(NFSU2_DIK_LSHIFT) == false);
    assert(nfsu2_input_active_count() == 1);
    
    printf("PASS: test_key_set_and_get\n");
}

static void test_steering_analog(void) {
    nfsu2_input_clear_all();
    
    // Hard left: -1.0
    nfsu2_input_set_steering(-1.0f);
    assert(nfsu2_input_get_key(NFSU2_DIK_LEFT) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_A) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_RIGHT) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_D) == false);
    
    // Hard right: +1.0
    nfsu2_input_set_steering(1.0f);
    assert(nfsu2_input_get_key(NFSU2_DIK_LEFT) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_A) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_RIGHT) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_D) == true);
    
    // Deadzone: 0.0
    nfsu2_input_set_steering(0.0f);
    assert(nfsu2_input_get_key(NFSU2_DIK_LEFT) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_A) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_RIGHT) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_D) == false);
    
    printf("PASS: test_steering_analog\n");
}

static void test_pedals_analog(void) {
    nfsu2_input_clear_all();
    
    // Throttle press
    nfsu2_input_set_throttle(0.85f);
    assert(nfsu2_input_get_key(NFSU2_DIK_UP) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_W) == true);
    
    // Throttle release
    nfsu2_input_set_throttle(0.02f);
    assert(nfsu2_input_get_key(NFSU2_DIK_UP) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_W) == false);
    
    // Brake press
    nfsu2_input_set_brake(0.90f);
    assert(nfsu2_input_get_key(NFSU2_DIK_DOWN) == true);
    assert(nfsu2_input_get_key(NFSU2_DIK_S) == true);
    
    // Brake release
    nfsu2_input_set_brake(0.0f);
    assert(nfsu2_input_get_key(NFSU2_DIK_DOWN) == false);
    assert(nfsu2_input_get_key(NFSU2_DIK_S) == false);
    
    printf("PASS: test_pedals_analog\n");
}

static void test_metal_fill_keyboard_compat(void) {
    nfsu2_input_clear_all();
    nfsu2_input_set_key(NFSU2_DIK_SPACE, true);
    nfsu2_input_set_key(NFSU2_DIK_ESCAPE, true);
    
    unsigned char buf[256];
    memset(buf, 0, sizeof(buf));
    metal_fill_keyboard(buf, 256);
    
    assert(buf[NFSU2_DIK_SPACE] == 0x80);
    assert(buf[NFSU2_DIK_ESCAPE] == 0x80);
    assert(buf[NFSU2_DIK_RETURN] == 0x00);
    
    printf("PASS: test_metal_fill_keyboard_compat\n");
}

static void test_metal_available(void) {
    assert(metal_available() == 1);
    printf("PASS: test_metal_available\n");
}

static void test_guest_memory_sync(void) {
    size_t test_size = NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + 512;
    uint8_t *sim_vm = (uint8_t *)calloc(1, test_size);
    assert(sim_vm != NULL);

    g_mem = sim_vm;
    uint32_t granule = NFSU2_KEYBOARD_BUFFER_GUEST_ADDR >> 14;
    g_cbits[granule >> 3] |= (uint8_t)(1u << (granule & 7));

    nfsu2_input_clear_all();
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_UP] == 0x00);

    /* Press UP (Gas) and SPACE (Handbrake) */
    nfsu2_input_set_key(NFSU2_DIK_UP, true);
    nfsu2_input_set_key(NFSU2_DIK_SPACE, true);

    /* Verify immediate mirror in guest memory at 0x00870990 */
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_UP] == 0x80);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_SPACE] == 0x80);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_DOWN] == 0x00);

    /* Test steering updates mirror in guest memory */
    nfsu2_input_set_steering(-1.0f);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_LEFT] == 0x80);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_A] == 0x80);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_RIGHT] == 0x00);

    /* Test clear all clears guest memory */
    nfsu2_input_clear_all();
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_UP] == 0x00);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_SPACE] == 0x00);
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_LEFT] == 0x00);

    /* Test nfsu2_input_sync_guest_memory */
    nfsu2_input_set_key(NFSU2_DIK_ESCAPE, true);
    /* Invalidate guest byte to verify sync flushes it */
    sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_ESCAPE] = 0x00;
    nfsu2_input_sync_guest_memory();
    assert(sim_vm[NFSU2_KEYBOARD_BUFFER_GUEST_ADDR + NFSU2_DIK_ESCAPE] == 0x80);

    nfsu2_input_clear_all();
    free(sim_vm);
    g_mem = NULL;
    memset(g_cbits, 0, sizeof(g_cbits));

    printf("PASS: test_guest_memory_sync\n");
}

int main(void) {
    printf("=== Running NFSU2InputBridge Tests ===\n");
    test_initial_and_clear();
    test_key_set_and_get();
    test_steering_analog();
    test_pedals_analog();
    test_metal_fill_keyboard_compat();
    test_metal_available();
    test_guest_memory_sync();
    printf("=== All NFSU2InputBridge Tests PASSED ===\n");
    return 0;
}
