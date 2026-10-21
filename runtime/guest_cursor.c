/*
 * NFSU2 Guest Runtime - Thread-Safe Cursor & Pointer State Implementation
 *
 * Implements atomic cursor tracking, viewport scaling, opt-in synthetic test
 * injection, and Win32 USER32 cursor imports (GetCursorPos, SetCursorPos, ShowCursor).
 */

#include "guest_cursor.h"
#include "guest_memory.h"
#include <stdatomic.h>
#include <string.h>
#include <math.h>

static inline uint32_t read32(const void *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static inline void write32(void *p, uint32_t v) {
    memcpy(p, &v, 4);
}

/*
 * C11 atomic packed 64-bit coordinate state:
 * High 32 bits: int32_t x
 * Low 32 bits:  int32_t y
 * Guarantees zero-torn-read updates across concurrent threads.
 */
static _Atomic uint64_t g_packed_coords = 0;
static _Atomic uint32_t g_cursor_flags = GUEST_CURSOR_FLAG_AVAILABLE | GUEST_CURSOR_FLAG_VISIBLE;
static _Atomic int32_t  g_display_count = 0;

/* Viewport metrics */
static _Atomic uint32_t g_viewport_w = 1280;
static _Atomic uint32_t g_viewport_h = 720;
static _Atomic uint32_t g_game_w     = 1280;
static _Atomic uint32_t g_game_h     = 720;
static _Atomic uint32_t g_scale_mode = GUEST_CURSOR_SCALE_FIT;

/* Synthetic test injection state (strictly opt-in) */
static _Atomic uint64_t g_synthetic_coords = 0;
static _Atomic uint32_t g_synthetic_flags  = 0;

/* DirectInput relative mouse deltas and previous coordinates */
static _Atomic int32_t g_mouse_dx   = 0;
static _Atomic int32_t g_mouse_dy   = 0;
static _Atomic int32_t g_prev_x      = 0;
static _Atomic int32_t g_prev_y      = 0;
static _Atomic bool    g_prev_valid  = false;

static inline uint64_t pack_coords(int32_t x, int32_t y) {
    return ((uint64_t)(uint32_t)x << 32) | ((uint64_t)(uint32_t)y & 0xffffffffULL);
}

static inline GuestCursorCoords unpack_coords(uint64_t packed) {
    GuestCursorCoords c;
    c.x = (int32_t)(packed >> 32);
    c.y = (int32_t)(packed & 0xffffffffULL);
    return c;
}

static int set_cursor_last_error(CPU *c, uint32_t error_code, uint32_t *fault) {
    if (!c->fs_base) {
        *fault = 0;
        return -2;
    }
    uint64_t teb_error = (uint64_t)c->fs_base + 0x34ULL;
    if (teb_error + 4ULL > 0x100000000ULL) {
        *fault = (teb_error > UINT32_MAX) ? UINT32_MAX : (uint32_t)teb_error;
        return -1;
    }
    uint8_t *error_ptr = guest_memory_pointer((uint32_t)teb_error, 4u, 1);
    if (!error_ptr) {
        *fault = (uint32_t)teb_error;
        return -1;
    }
    write32(error_ptr, error_code);
    return 0;
}

void guest_cursor_init(void) {
    atomic_store_explicit(&g_packed_coords, 0, memory_order_relaxed);
    atomic_store_explicit(&g_cursor_flags, GUEST_CURSOR_FLAG_AVAILABLE | GUEST_CURSOR_FLAG_VISIBLE, memory_order_relaxed);
    atomic_store_explicit(&g_display_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_synthetic_coords, 0, memory_order_relaxed);
    atomic_store_explicit(&g_synthetic_flags, 0, memory_order_relaxed);
    atomic_store_explicit(&g_viewport_w, 1280, memory_order_relaxed);
    atomic_store_explicit(&g_viewport_h, 720, memory_order_relaxed);
    atomic_store_explicit(&g_game_w, 1280, memory_order_relaxed);
    atomic_store_explicit(&g_game_h, 720, memory_order_relaxed);
    atomic_store_explicit(&g_scale_mode, GUEST_CURSOR_SCALE_FIT, memory_order_relaxed);
    atomic_store_explicit(&g_mouse_dx, 0, memory_order_relaxed);
    atomic_store_explicit(&g_mouse_dy, 0, memory_order_relaxed);
    atomic_store_explicit(&g_prev_x, 0, memory_order_relaxed);
    atomic_store_explicit(&g_prev_y, 0, memory_order_relaxed);
    atomic_store_explicit(&g_prev_valid, false, memory_order_relaxed);
}

void guest_cursor_reset(void) {
    guest_cursor_init();
}

void guest_cursor_set_viewport(uint32_t viewport_w, uint32_t viewport_h,
                               uint32_t game_w, uint32_t game_h,
                               GuestCursorScalingMode mode) {
    if (!viewport_w || !viewport_h || !game_w || !game_h) return;
    atomic_store_explicit(&g_viewport_w, viewport_w, memory_order_relaxed);
    atomic_store_explicit(&g_viewport_h, viewport_h, memory_order_relaxed);
    atomic_store_explicit(&g_game_w, game_w, memory_order_relaxed);
    atomic_store_explicit(&g_game_h, game_h, memory_order_relaxed);
    atomic_store_explicit(&g_scale_mode, (uint32_t)mode, memory_order_relaxed);
}

void guest_cursor_host_to_game(float host_x, float host_y, int32_t *game_x, int32_t *game_y) {
    float vw = (float)atomic_load_explicit(&g_viewport_w, memory_order_relaxed);
    float vh = (float)atomic_load_explicit(&g_viewport_h, memory_order_relaxed);
    float gw = (float)atomic_load_explicit(&g_game_w, memory_order_relaxed);
    float gh = (float)atomic_load_explicit(&g_game_h, memory_order_relaxed);
    uint32_t mode = atomic_load_explicit(&g_scale_mode, memory_order_relaxed);

    float gx = 0.0f, gy = 0.0f;
    if (mode == GUEST_CURSOR_SCALE_FIT) {
        float scale = fminf(vw / gw, vh / gh);
        if (scale < 0.0001f) scale = 1.0f;
        float offset_x = (vw - gw * scale) * 0.5f;
        float offset_y = (vh - gh * scale) * 0.5f;
        gx = (host_x - offset_x) / scale;
        gy = (host_y - offset_y) / scale;
    } else {
        gx = host_x * (gw / vw);
        gy = host_y * (gh / vh);
    }

    /* Clamp within game bounds */
    if (gx < 0.0f) gx = 0.0f;
    if (gx > gw - 1.0f) gx = gw - 1.0f;
    if (gy < 0.0f) gy = 0.0f;
    if (gy > gh - 1.0f) gy = gh - 1.0f;

    /* Positive coordinate rounding without requiring libm (e.g. lroundf) */
    if (game_x) *game_x = (int32_t)(gx + 0.5f);
    if (game_y) *game_y = (int32_t)(gy + 0.5f);
}

void guest_cursor_game_to_host(int32_t game_x, int32_t game_y, float *host_x, float *host_y) {
    float vw = (float)atomic_load_explicit(&g_viewport_w, memory_order_relaxed);
    float vh = (float)atomic_load_explicit(&g_viewport_h, memory_order_relaxed);
    float gw = (float)atomic_load_explicit(&g_game_w, memory_order_relaxed);
    float gh = (float)atomic_load_explicit(&g_game_h, memory_order_relaxed);
    uint32_t mode = atomic_load_explicit(&g_scale_mode, memory_order_relaxed);

    float hx = 0.0f, hy = 0.0f;
    if (mode == GUEST_CURSOR_SCALE_FIT) {
        float scale = fminf(vw / gw, vh / gh);
        if (scale < 0.0001f) scale = 1.0f;
        float offset_x = (vw - gw * scale) * 0.5f;
        float offset_y = (vh - gh * scale) * 0.5f;
        hx = (float)game_x * scale + offset_x;
        hy = (float)game_y * scale + offset_y;
    } else {
        hx = (float)game_x * (vw / gw);
        hy = (float)game_y * (vh / gh);
    }

    if (host_x) *host_x = hx;
    if (host_y) *host_y = hy;
}

void guest_cursor_set_host_pos(float host_x, float host_y, bool is_down) {
    if (atomic_load_explicit(&g_cursor_flags, memory_order_acquire) & GUEST_CURSOR_FLAG_SYNTHETIC) {
        return;
    }
    int32_t gx = 0, gy = 0;
    guest_cursor_host_to_game(host_x, host_y, &gx, &gy);
    atomic_store_explicit(&g_packed_coords, pack_coords(gx, gy), memory_order_release);

    if (atomic_load_explicit(&g_prev_valid, memory_order_relaxed)) {
        int32_t prev_x = atomic_load_explicit(&g_prev_x, memory_order_relaxed);
        int32_t prev_y = atomic_load_explicit(&g_prev_y, memory_order_relaxed);
        int32_t dx = gx - prev_x;
        int32_t dy = gy - prev_y;
        atomic_fetch_add_explicit(&g_mouse_dx, dx, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_mouse_dy, dy, memory_order_relaxed);
    } else {
        atomic_store_explicit(&g_prev_valid, true, memory_order_relaxed);
    }
    atomic_store_explicit(&g_prev_x, gx, memory_order_relaxed);
    atomic_store_explicit(&g_prev_y, gy, memory_order_relaxed);

    uint32_t flags = atomic_load_explicit(&g_cursor_flags, memory_order_relaxed);
    flags |= GUEST_CURSOR_FLAG_AVAILABLE;
    if (is_down) flags |= GUEST_CURSOR_FLAG_DOWN;
    else flags &= ~GUEST_CURSOR_FLAG_DOWN;
    atomic_store_explicit(&g_cursor_flags, flags, memory_order_release);
}

void guest_cursor_set_available(bool available) {
    if (!available) {
        atomic_store_explicit(&g_prev_valid, false, memory_order_relaxed);
    }
    uint32_t flags = atomic_load_explicit(&g_cursor_flags, memory_order_relaxed);
    if (available) flags |= GUEST_CURSOR_FLAG_AVAILABLE;
    else flags &= ~GUEST_CURSOR_FLAG_AVAILABLE;
    atomic_store_explicit(&g_cursor_flags, flags, memory_order_release);
}

void guest_cursor_inject_synthetic(int32_t x, int32_t y, uint32_t flags) {
    atomic_store_explicit(&g_synthetic_coords, pack_coords(x, y), memory_order_release);
    atomic_store_explicit(&g_synthetic_flags, flags | GUEST_CURSOR_FLAG_SYNTHETIC, memory_order_release);
    uint32_t cur = atomic_load_explicit(&g_cursor_flags, memory_order_relaxed);
    atomic_store_explicit(&g_cursor_flags, cur | GUEST_CURSOR_FLAG_SYNTHETIC, memory_order_release);
}

void guest_cursor_clear_synthetic(void) {
    uint32_t cur = atomic_load_explicit(&g_cursor_flags, memory_order_relaxed);
    atomic_store_explicit(&g_cursor_flags, cur & ~GUEST_CURSOR_FLAG_SYNTHETIC, memory_order_release);
    atomic_store_explicit(&g_synthetic_flags, 0, memory_order_relaxed);
}

bool guest_cursor_is_synthetic(void) {
    return (atomic_load_explicit(&g_cursor_flags, memory_order_acquire) & GUEST_CURSOR_FLAG_SYNTHETIC) != 0;
}

GuestCursorCoords guest_cursor_get_coords(void) {
    uint32_t flags = atomic_load_explicit(&g_cursor_flags, memory_order_acquire);
    uint64_t packed = (flags & GUEST_CURSOR_FLAG_SYNTHETIC)
                    ? atomic_load_explicit(&g_synthetic_coords, memory_order_acquire)
                    : atomic_load_explicit(&g_packed_coords, memory_order_acquire);
    return unpack_coords(packed);
}

uint32_t guest_cursor_get_flags(void) {
    uint32_t flags = atomic_load_explicit(&g_cursor_flags, memory_order_acquire);
    if (flags & GUEST_CURSOR_FLAG_SYNTHETIC) {
        return flags | atomic_load_explicit(&g_synthetic_flags, memory_order_acquire);
    }
    return flags;
}

int32_t guest_cursor_get_display_count(void) {
    return atomic_load_explicit(&g_display_count, memory_order_relaxed);
}

/*
 * Win32 USER32!GetCursorPos(LPPOINT lpPoint)
 * Stdcall ABI: 1 arg, pop 4 bytes (frame = return_ip + lpPoint = 8 bytes).
 */
int guest_user32_get_cursor_pos(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (!c || !import || !import->name || !fault) return 0;
    if (strcmp(import->name, "GetCursorPos") != 0) return 0;

    const uint8_t *frame = guest_memory_pointer(c->esp, 8, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip   = read32(frame);
    uint32_t lp_point = read32(frame + 4);

    if (lp_point == 0) {
        /* Windows reports ERROR_NOACCESS (998) when lpPoint is NULL. */
        int rc = set_cursor_last_error(c, 998u, fault);
        if (rc) return rc;
        c->eax = 0;       /* FALSE */
        c->eip = ret_ip;
        c->esp += 8u;
        return 1;
    }

    if ((uint64_t)lp_point + 8u > 0x100000000ULL) {
        *fault = lp_point;
        return -1;
    }

    void *dst = guest_memory_pointer(lp_point, 8, 1);
    if (!dst) {
        *fault = lp_point;
        return -1;
    }

    GuestCursorCoords coords = guest_cursor_get_coords();
    write32(dst, (uint32_t)coords.x);
    write32((uint8_t *)dst + 4, (uint32_t)coords.y);

    c->eax = 1;           /* TRUE */
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

/*
 * Win32 USER32!SetCursorPos(int x, int y)
 * Stdcall ABI: 2 args, pop 8 bytes (frame = return_ip + x + y = 12 bytes).
 */
int guest_user32_set_cursor_pos(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (!c || !import || !import->name || !fault) return 0;
    if (strcmp(import->name, "SetCursorPos") != 0) return 0;

    const uint8_t *frame = guest_memory_pointer(c->esp, 12, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip = read32(frame);
    int32_t x       = (int32_t)read32(frame + 4);
    int32_t y       = (int32_t)read32(frame + 8);

    if (!guest_cursor_is_synthetic()) {
        atomic_store_explicit(&g_packed_coords, pack_coords(x, y), memory_order_release);
        atomic_store_explicit(&g_prev_x, x, memory_order_relaxed);
        atomic_store_explicit(&g_prev_y, y, memory_order_relaxed);
        atomic_store_explicit(&g_prev_valid, true, memory_order_relaxed);
    }

    c->eax = 1;           /* TRUE */
    c->eip = ret_ip;
    c->esp += 12u;
    return 1;
}

/*
 * Win32 USER32!ShowCursor(BOOL bShow)
 * Stdcall ABI: 1 arg, pop 4 bytes (frame = return_ip + bShow = 8 bytes).
 */
int guest_user32_show_cursor(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (!c || !import || !import->name || !fault) return 0;
    if (strcmp(import->name, "ShowCursor") != 0) return 0;

    const uint8_t *frame = guest_memory_pointer(c->esp, 8, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip = read32(frame);
    uint32_t b_show = read32(frame + 4);

    int32_t count = b_show ? atomic_fetch_add_explicit(&g_display_count, 1, memory_order_relaxed) + 1
                           : atomic_fetch_sub_explicit(&g_display_count, 1, memory_order_relaxed) - 1;

    uint32_t flags = atomic_load_explicit(&g_cursor_flags, memory_order_relaxed);
    if (count >= 0) flags |= GUEST_CURSOR_FLAG_VISIBLE;
    else flags &= ~GUEST_CURSOR_FLAG_VISIBLE;
    atomic_store_explicit(&g_cursor_flags, flags, memory_order_release);

    c->eax = (uint32_t)count;
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

/*
 * Legacy / Bridge hooks compatibility:
 * If metal.m or com.c calls metal_get_cursor, connect to guest_cursor.
 */
void metal_get_cursor(int *x, int *y) {
    GuestCursorCoords coords = guest_cursor_get_coords();
    if (x) *x = coords.x;
    if (y) *y = coords.y;
}

/*
 * DirectInput 8 Mouse Emulation:
 * DirectInput COM emulation in runtime/com.c calls metal_fill_mouse(dst, cb)
 * for cb == 20 (DIMOUSESTATE2) and cb == 16 (DIMOUSESTATE).
 *
 * Buffer layout (DIMOUSESTATE2, 20 bytes):
 *   +0  LONG lX (relative delta X)
 *   +4  LONG lY (relative delta Y)
 *   +8  LONG lZ (relative delta Z / scroll wheel)
 *   +12 BYTE rgbButtons[8] (button 0 = 0x80 when down, buttons 1..7 = 0x00)
 */
void metal_fill_mouse(unsigned char *dst, unsigned int n) {
    if (!dst || n < 20) return;
    int32_t dx = atomic_exchange_explicit(&g_mouse_dx, 0, memory_order_acq_rel);
    int32_t dy = atomic_exchange_explicit(&g_mouse_dy, 0, memory_order_acq_rel);
    int32_t dz = 0;
    memcpy(dst + 0, &dx, 4);
    memcpy(dst + 4, &dy, 4);
    memcpy(dst + 8, &dz, 4);
    uint32_t flags = guest_cursor_get_flags();
    dst[12] = (flags & GUEST_CURSOR_FLAG_DOWN) ? 0x80 : 0x00; /* Button 0 (left click) */
    for (int i = 1; i < 8; i++) dst[12 + i] = 0x00;
}

void metal_mouse_add(int dx, int dy) {
    atomic_fetch_add_explicit(&g_mouse_dx, dx, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_mouse_dy, dy, memory_order_relaxed);
}
