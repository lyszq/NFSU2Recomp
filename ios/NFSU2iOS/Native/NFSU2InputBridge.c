/*
 * NFSU2 iOS Port - DirectInput Klavye ve Kontrolcü Köprüsü Uygulaması
 *
 * C11 atomik bellek modeli ile kilitsiz (lock-free), sıfır gecikmeli (zero-latency)
 * tuş dizisi yönetimi sağlar. DirectInput (cb=256) GetDeviceState çağrılarını
 * ve SPEED2.EXE içindeki 0x00870990 statik klavye tamponunu doğrudan besler.
 */

#include "NFSU2InputBridge.h"
#include "guest_cursor.h"
#include "guest_memory.h"
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

void nfsu2_input_sync_guest_memory(void) {
    /* Documented no-op: SPEED2.EXE reads DirectInput keyboard states through
     * IDirectInputDevice8::GetDeviceState, which calls metal_fill_keyboard. */
}

void nfsu2_input_set_steering(float analog_x) {
    /* Hassas ölü bölge (deadzone) eşiği */
    const float deadzone = 0.08f;
    if (analog_x < -deadzone) {
        /* Sol yön aktif: hem DIK_LEFT hem de ikincil tuş DIK_A */
        nfsu2_input_set_key(NFSU2_DIK_LEFT, true);
        nfsu2_input_set_key(NFSU2_DIK_A, true);
        nfsu2_input_set_key(NFSU2_DIK_RIGHT, false);
        nfsu2_input_set_key(NFSU2_DIK_D, false);
    } else if (analog_x > deadzone) {
        /* Sağ yön aktif: hem DIK_RIGHT hem de ikincil tuş DIK_D */
        nfsu2_input_set_key(NFSU2_DIK_RIGHT, true);
        nfsu2_input_set_key(NFSU2_DIK_D, true);
        nfsu2_input_set_key(NFSU2_DIK_LEFT, false);
        nfsu2_input_set_key(NFSU2_DIK_A, false);
    } else {
        /* Ölü bölge içinde (merkez): direksiyon tuşlarını serbest bırak */
        nfsu2_input_set_key(NFSU2_DIK_LEFT, false);
        nfsu2_input_set_key(NFSU2_DIK_A, false);
        nfsu2_input_set_key(NFSU2_DIK_RIGHT, false);
        nfsu2_input_set_key(NFSU2_DIK_D, false);
    }
}

void nfsu2_input_set_throttle(float analog_val) {
    const float threshold = 0.08f;
    bool pressed = (analog_val > threshold);
    nfsu2_input_set_key(NFSU2_DIK_UP, pressed);
    nfsu2_input_set_key(NFSU2_DIK_W, pressed);
}

void nfsu2_input_set_brake(float analog_val) {
    const float threshold = 0.08f;
    bool pressed = (analog_val > threshold);
    nfsu2_input_set_key(NFSU2_DIK_DOWN, pressed);
    nfsu2_input_set_key(NFSU2_DIK_S, pressed);
}

/*
 * runtime/com.c IDirectInputDevice8::GetDeviceState ve GetDeviceData çağrıları
 * metal_fill_keyboard() fonksiyonunu çağırır. Bu fonksiyon tamponu doğrudan doldurur.
 */
void metal_fill_keyboard(unsigned char *dst, unsigned int n) {
    nfsu2_input_fill_keyboard((uint8_t *)dst, (uint32_t)n);
}

/*
 * runtime/com.c uyumluluğu: DirectInput hook'larının metal_fill_keyboard()
 * çağrısını yapabilmesi için metal_available() gereklidir.
 */
int metal_available(void) {
    return 1;
}

void nfsu2_input_set_cursor(float host_x, float host_y, bool is_down) {
    guest_cursor_set_host_pos(host_x, host_y, is_down);
}

void nfsu2_input_set_cursor_available(bool available) {
    guest_cursor_set_available(available);
}

bool nfsu2_input_get_cursor(int *x, int *y) {
    GuestCursorCoords coords = guest_cursor_get_coords();
    if (x) *x = coords.x;
    if (y) *y = coords.y;
    return (guest_cursor_get_flags() & GUEST_CURSOR_FLAG_AVAILABLE) != 0;
}

void nfsu2_input_set_viewport(uint32_t viewport_w, uint32_t viewport_h,
                               uint32_t game_w, uint32_t game_h) {
    guest_cursor_set_viewport(viewport_w, viewport_h, game_w, game_h, GUEST_CURSOR_SCALE_FIT);
}
