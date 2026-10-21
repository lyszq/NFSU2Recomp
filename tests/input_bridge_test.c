/*
 * Test suite for NFSU2InputBridge (DirectInput DIK_* key table & analog mapping)
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../ios/NFSU2iOS/Native/NFSU2InputBridge.h"

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

int main(void) {
    printf("=== Running NFSU2InputBridge Tests ===\n");
    test_initial_and_clear();
    test_key_set_and_get();
    test_steering_analog();
    test_pedals_analog();
    test_metal_fill_keyboard_compat();
    printf("=== All NFSU2InputBridge Tests PASSED ===\n");
    return 0;
}
