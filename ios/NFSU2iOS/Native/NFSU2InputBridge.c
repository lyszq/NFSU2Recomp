/*
 * NFSU2 iOS Port - DirectInput Klavye ve Kontrolcü Köprüsü Uygulaması
 *
 * C11 atomik bellek modeli ile kilitsiz (lock-free), sıfır gecikmeli (zero-latency)
 * tuş dizisi yönetimi sağlar.
 */

#include "NFSU2InputBridge.h"
#include <stdatomic.h>
#include <string.h>

/*
 * DirectInput 8 klavye durumu için 256 baytlık atomik tablo.
 * Her eleman 1 (basılı) veya 0 (serbest) tutar.
 * DirectInput standart GetDeviceState ve GetDeviceData çağrılarında
 * basılı tuşlar için en yüksek bit olan 0x80 beklenir.
 */
static _Atomic uint8_t g_keys[256];

void nfsu2_input_set_key(uint8_t dik_code, bool is_pressed) {
    atomic_store_explicit(&g_keys[dik_code], is_pressed ? 1 : 0, memory_order_release);
}

void nfsu2_input_clear_all(void) {
    for (int i = 0; i < 256; i++) {
        atomic_store_explicit(&g_keys[i], 0, memory_order_relaxed);
    }
}

bool nfsu2_input_get_key(uint8_t dik_code) {
    return atomic_load_explicit(&g_keys[dik_code], memory_order_acquire) != 0;
}

uint32_t nfsu2_input_active_count(void) {
    uint32_t count = 0;
    for (int i = 0; i < 256; i++) {
        if (atomic_load_explicit(&g_keys[i], memory_order_relaxed)) {
            count++;
        }
    }
    return count;
}

void nfsu2_input_fill_keyboard(uint8_t *dst, uint32_t count) {
    if (!dst) return;
    if (count > 256) count = 256;
    for (uint32_t i = 0; i < count; i++) {
        dst[i] = atomic_load_explicit(&g_keys[i], memory_order_acquire) ? 0x80 : 0x00;
    }
}

void nfsu2_input_set_steering(float analog_x) {
    /* Hassas ölü bölge (deadzone) eşiği */
    const float deadzone = 0.08f;
    if (analog_x < -deadzone) {
        /* Sol yön aktif: hem DIK_LEFT hem de ikincil tuş DIK_A */
        atomic_store_explicit(&g_keys[NFSU2_DIK_LEFT], 1, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_A], 1, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_RIGHT], 0, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_D], 0, memory_order_release);
    } else if (analog_x > deadzone) {
        /* Sağ yön aktif: hem DIK_RIGHT hem de ikincil tuş DIK_D */
        atomic_store_explicit(&g_keys[NFSU2_DIK_RIGHT], 1, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_D], 1, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_LEFT], 0, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_A], 0, memory_order_release);
    } else {
        /* Ölü bölge içinde (merkez): direksiyon tuşlarını serbest bırak */
        atomic_store_explicit(&g_keys[NFSU2_DIK_LEFT], 0, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_A], 0, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_RIGHT], 0, memory_order_release);
        atomic_store_explicit(&g_keys[NFSU2_DIK_D], 0, memory_order_release);
    }
}

void nfsu2_input_set_throttle(float analog_val) {
    const float threshold = 0.08f;
    uint8_t state = (analog_val > threshold) ? 1 : 0;
    atomic_store_explicit(&g_keys[NFSU2_DIK_UP], state, memory_order_release);
    atomic_store_explicit(&g_keys[NFSU2_DIK_W], state, memory_order_release);
}

void nfsu2_input_set_brake(float analog_val) {
    const float threshold = 0.08f;
    uint8_t state = (analog_val > threshold) ? 1 : 0;
    atomic_store_explicit(&g_keys[NFSU2_DIK_DOWN], state, memory_order_release);
    atomic_store_explicit(&g_keys[NFSU2_DIK_S], state, memory_order_release);
}

/*
 * runtime/com.c IDirectInputDevice8::GetDeviceState ve GetDeviceData çağrıları
 * metal_fill_keyboard() fonksiyonunu çağırır. Bu fonksiyon tamponu doğrudan doldurur.
 */
void metal_fill_keyboard(unsigned char *dst, unsigned int n) {
    nfsu2_input_fill_keyboard((uint8_t *)dst, (uint32_t)n);
}
