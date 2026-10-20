/*
 * NFSU2 iOS Port - DirectInput Klavye ve Kontrolcü Köprüsü Uygulaması
 */

#include "NFSU2InputBridge.h"
#include <stdatomic.h>
#include <string.h>

/*
 * DirectInput 8 klavye durumu için 256 baytlık atomik tablo.
 * Her eleman 1 (basılı) veya 0 (serbest) tutar.
 * DirectInput standart GetDeviceState çağrısında basılı tuşlar için en yüksek
 * bit olan 0x80 beklenir.
 */
static _Atomic uint8_t g_keys[256];

void nfsu2_input_set_key(uint8_t dik_code, bool is_pressed) {
    atomic_store(&g_keys[dik_code], is_pressed ? 1 : 0);
}

void nfsu2_input_clear_all(void) {
    for (int i = 0; i < 256; i++) {
        atomic_store(&g_keys[i], 0);
    }
}

bool nfsu2_input_get_key(uint8_t dik_code) {
    return atomic_load(&g_keys[dik_code]) != 0;
}

void nfsu2_input_fill_keyboard(uint8_t *dst, uint32_t count) {
    if (!dst) return;
    if (count > 256) count = 256;
    for (uint32_t i = 0; i < count; i++) {
        dst[i] = atomic_load(&g_keys[i]) ? 0x80 : 0x00;
    }
}

void nfsu2_input_set_steering(float analog_x) {
    const float deadzone = 0.20f;
    if (analog_x < -deadzone) {
        /* Sol: hem sol ok hem de 'A' tuşunu etkinleştir */
        atomic_store(&g_keys[NFSU2_DIK_LEFT], 1);
        atomic_store(&g_keys[NFSU2_DIK_A], 1);
        atomic_store(&g_keys[NFSU2_DIK_RIGHT], 0);
        atomic_store(&g_keys[NFSU2_DIK_D], 0);
    } else if (analog_x > deadzone) {
        /* Sağ: hem sağ ok hem de 'D' tuşunu etkinleştir */
        atomic_store(&g_keys[NFSU2_DIK_RIGHT], 1);
        atomic_store(&g_keys[NFSU2_DIK_D], 1);
        atomic_store(&g_keys[NFSU2_DIK_LEFT], 0);
        atomic_store(&g_keys[NFSU2_DIK_A], 0);
    } else {
        /* Merkezde (ölü bölge): iki yönü de serbest bırak */
        atomic_store(&g_keys[NFSU2_DIK_LEFT], 0);
        atomic_store(&g_keys[NFSU2_DIK_A], 0);
        atomic_store(&g_keys[NFSU2_DIK_RIGHT], 0);
        atomic_store(&g_keys[NFSU2_DIK_D], 0);
    }
}

void nfsu2_input_set_throttle(float analog_val) {
    const float threshold = 0.15f;
    uint8_t state = (analog_val > threshold) ? 1 : 0;
    atomic_store(&g_keys[NFSU2_DIK_UP], state);
    atomic_store(&g_keys[NFSU2_DIK_W], state);
}

void nfsu2_input_set_brake(float analog_val) {
    const float threshold = 0.15f;
    uint8_t state = (analog_val > threshold) ? 1 : 0;
    atomic_store(&g_keys[NFSU2_DIK_DOWN], state);
    atomic_store(&g_keys[NFSU2_DIK_S], state);
}

/*
 * runtime/com.c IDirectInputDevice8::GetDeviceState ve GetDeviceData çağrıları
 * metal_fill_keyboard() fonksiyonunu çağırır. Bu fonksiyon tamponu doldurur.
 */
void metal_fill_keyboard(unsigned char *dst, unsigned int n) {
    nfsu2_input_fill_keyboard((uint8_t *)dst, (uint32_t)n);
}
