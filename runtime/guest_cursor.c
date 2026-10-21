/*
 * NFSU2 Guest Runtime - Synchronized cursor and pointer state.
 *
 * Coordinates, availability, viewport mapping, display count, and relative
 * mouse state share one mutex so UI ingress and guest reads see coherent data.
 * Synthetic startup fixtures are thread-local and never modify live state.
 */

#include "guest_cursor.h"
#include "guest_memory.h"
#include <math.h>
#include <pthread.h>
#include <string.h>

typedef struct GuestCursorLiveState {
    int32_t x;
    int32_t y;
    bool position_valid;
    uint32_t flags;
    int32_t display_count;

    uint32_t viewport_w;
    uint32_t viewport_h;
    uint32_t game_w;
    uint32_t game_h;
    GuestCursorScalingMode scale_mode;

    int32_t mouse_dx;
    int32_t mouse_dy;
    int32_t previous_x;
    int32_t previous_y;
    bool previous_valid;
} GuestCursorLiveState;

typedef struct GuestCursorSyntheticState {
    GuestCursorCoords coords;
    uint32_t flags;
    int32_t display_count;
    int32_t mouse_dx;
    int32_t mouse_dy;
    bool active;
} GuestCursorSyntheticState;

static pthread_mutex_t g_cursor_mutex = PTHREAD_MUTEX_INITIALIZER;
static GuestCursorLiveState g_cursor_state = {
    .flags = GUEST_CURSOR_FLAG_VISIBLE,
    .viewport_w = 1280,
    .viewport_h = 720,
    .game_w = 1280,
    .game_h = 720,
    .scale_mode = GUEST_CURSOR_SCALE_FIT
};
static _Thread_local GuestCursorSyntheticState g_synthetic_state;

static inline uint32_t read32(const void *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void write32(void *p, uint32_t v) {
    memcpy(p, &v, sizeof(v));
}

static int32_t saturating_add_i32(int32_t a, int64_t b) {
    int64_t sum = (int64_t)a + b;
    if (sum > INT32_MAX) return INT32_MAX;
    if (sum < INT32_MIN) return INT32_MIN;
    return (int32_t)sum;
}

static int32_t rounded_game_coord(double value, uint32_t dimension) {
    if (!isfinite(value) || value <= 0.0 || dimension == 0) return 0;

    double maximum = (double)dimension - 1.0;
    if (maximum > (double)INT32_MAX) maximum = (double)INT32_MAX;
    if (value >= maximum) return (int32_t)maximum;

    double rounded = value + 0.5;
    if (rounded >= maximum) return (int32_t)maximum;
    return (int32_t)rounded;
}

static void host_to_game_locked(float host_x, float host_y,
                                int32_t *game_x, int32_t *game_y) {
    const double vw = (double)g_cursor_state.viewport_w;
    const double vh = (double)g_cursor_state.viewport_h;
    const double gw = (double)g_cursor_state.game_w;
    const double gh = (double)g_cursor_state.game_h;
    double gx = 0.0;
    double gy = 0.0;

    if (isfinite(host_x) && isfinite(host_y)) {
        if (g_cursor_state.scale_mode == GUEST_CURSOR_SCALE_FIT) {
            const double sx = vw / gw;
            const double sy = vh / gh;
            const double scale = sx < sy ? sx : sy;
            const double offset_x = (vw - gw * scale) * 0.5;
            const double offset_y = (vh - gh * scale) * 0.5;
            gx = ((double)host_x - offset_x) / scale;
            gy = ((double)host_y - offset_y) / scale;
        } else {
            gx = (double)host_x * (gw / vw);
            gy = (double)host_y * (gh / vh);
        }
    }

    if (game_x) *game_x = rounded_game_coord(gx, g_cursor_state.game_w);
    if (game_y) *game_y = rounded_game_coord(gy, g_cursor_state.game_h);
}

static void game_to_host_locked(int32_t game_x, int32_t game_y,
                                float *host_x, float *host_y) {
    const double vw = (double)g_cursor_state.viewport_w;
    const double vh = (double)g_cursor_state.viewport_h;
    const double gw = (double)g_cursor_state.game_w;
    const double gh = (double)g_cursor_state.game_h;
    double hx;
    double hy;

    if (g_cursor_state.scale_mode == GUEST_CURSOR_SCALE_FIT) {
        const double sx = vw / gw;
        const double sy = vh / gh;
        const double scale = sx < sy ? sx : sy;
        const double offset_x = (vw - gw * scale) * 0.5;
        const double offset_y = (vh - gh * scale) * 0.5;
        hx = (double)game_x * scale + offset_x;
        hy = (double)game_y * scale + offset_y;
    } else {
        hx = (double)game_x * (vw / gw);
        hy = (double)game_y * (vh / gh);
    }

    if (host_x) *host_x = (float)hx;
    if (host_y) *host_y = (float)hy;
}

static void store_position_locked(int32_t x, int32_t y) {
    if (g_cursor_state.previous_valid) {
        const int64_t dx = (int64_t)x - (int64_t)g_cursor_state.previous_x;
        const int64_t dy = (int64_t)y - (int64_t)g_cursor_state.previous_y;
        g_cursor_state.mouse_dx = saturating_add_i32(g_cursor_state.mouse_dx, dx);
        g_cursor_state.mouse_dy = saturating_add_i32(g_cursor_state.mouse_dy, dy);
    }

    g_cursor_state.x = x;
    g_cursor_state.y = y;
    g_cursor_state.position_valid = true;
    g_cursor_state.previous_x = x;
    g_cursor_state.previous_y = y;
    g_cursor_state.previous_valid = true;
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
    pthread_mutex_lock(&g_cursor_mutex);
    g_cursor_state = (GuestCursorLiveState){
        .flags = GUEST_CURSOR_FLAG_VISIBLE,
        .viewport_w = 1280,
        .viewport_h = 720,
        .game_w = 1280,
        .game_h = 720,
        .scale_mode = GUEST_CURSOR_SCALE_FIT
    };
    pthread_mutex_unlock(&g_cursor_mutex);
    guest_cursor_clear_synthetic();
}

void guest_cursor_reset(void) {
    guest_cursor_init();
}

void guest_cursor_set_viewport(uint32_t viewport_w, uint32_t viewport_h,
                               uint32_t game_w, uint32_t game_h,
                               GuestCursorScalingMode mode) {
    if (!viewport_w || !viewport_h || !game_w || !game_h) return;

    pthread_mutex_lock(&g_cursor_mutex);
    g_cursor_state.viewport_w = viewport_w;
    g_cursor_state.viewport_h = viewport_h;
    g_cursor_state.game_w = game_w;
    g_cursor_state.game_h = game_h;
    g_cursor_state.scale_mode = mode;
    pthread_mutex_unlock(&g_cursor_mutex);
}

void guest_cursor_host_to_game(float host_x, float host_y,
                               int32_t *game_x, int32_t *game_y) {
    pthread_mutex_lock(&g_cursor_mutex);
    host_to_game_locked(host_x, host_y, game_x, game_y);
    pthread_mutex_unlock(&g_cursor_mutex);
}

void guest_cursor_game_to_host(int32_t game_x, int32_t game_y,
                               float *host_x, float *host_y) {
    pthread_mutex_lock(&g_cursor_mutex);
    game_to_host_locked(game_x, game_y, host_x, host_y);
    pthread_mutex_unlock(&g_cursor_mutex);
}

void guest_cursor_set_host_pos(float host_x, float host_y, bool is_down) {
    if (!isfinite(host_x) || !isfinite(host_y)) return;

    pthread_mutex_lock(&g_cursor_mutex);
    int32_t x = 0;
    int32_t y = 0;
    host_to_game_locked(host_x, host_y, &x, &y);
    store_position_locked(x, y);
    g_cursor_state.flags |= GUEST_CURSOR_FLAG_AVAILABLE;
    if (is_down) g_cursor_state.flags |= GUEST_CURSOR_FLAG_DOWN;
    else g_cursor_state.flags &= ~GUEST_CURSOR_FLAG_DOWN;
    pthread_mutex_unlock(&g_cursor_mutex);
}

void guest_cursor_set_available(bool available) {
    pthread_mutex_lock(&g_cursor_mutex);
    if (available) {
        g_cursor_state.flags |= GUEST_CURSOR_FLAG_AVAILABLE;
    } else {
        g_cursor_state.flags &= ~(GUEST_CURSOR_FLAG_AVAILABLE | GUEST_CURSOR_FLAG_DOWN);
        g_cursor_state.position_valid = false;
        g_cursor_state.previous_valid = false;
    }
    pthread_mutex_unlock(&g_cursor_mutex);
}

void guest_cursor_inject_synthetic(int32_t x, int32_t y, uint32_t flags) {
    g_synthetic_state = (GuestCursorSyntheticState){
        .coords = {x, y},
        .flags = flags,
        .display_count = 0,
        .mouse_dx = 0,
        .mouse_dy = 0,
        .active = true
    };
}

void guest_cursor_clear_synthetic(void) {
    g_synthetic_state = (GuestCursorSyntheticState){0};
}

bool guest_cursor_is_synthetic(void) {
    return g_synthetic_state.active;
}

GuestCursorSnapshot guest_cursor_get_snapshot(void) {
    GuestCursorSnapshot snapshot;
    if (g_synthetic_state.active) {
        snapshot.coords = g_synthetic_state.coords;
        snapshot.flags = g_synthetic_state.flags;
        snapshot.position_valid = true;
        return snapshot;
    }

    pthread_mutex_lock(&g_cursor_mutex);
    snapshot.coords.x = g_cursor_state.x;
    snapshot.coords.y = g_cursor_state.y;
    snapshot.flags = g_cursor_state.flags;
    snapshot.position_valid = g_cursor_state.position_valid;
    pthread_mutex_unlock(&g_cursor_mutex);
    return snapshot;
}

GuestCursorCoords guest_cursor_get_coords(void) {
    return guest_cursor_get_snapshot().coords;
}

uint32_t guest_cursor_get_flags(void) {
    return guest_cursor_get_snapshot().flags;
}

int32_t guest_cursor_get_display_count(void) {
    if (g_synthetic_state.active) return g_synthetic_state.display_count;
    pthread_mutex_lock(&g_cursor_mutex);
    int32_t count = g_cursor_state.display_count;
    pthread_mutex_unlock(&g_cursor_mutex);
    return count;
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

    uint32_t ret_ip = read32(frame);
    uint32_t lp_point = read32(frame + 4);
    if (lp_point == 0) {
        /* Windows reports ERROR_NOACCESS (998) when lpPoint is NULL. */
        int rc = set_cursor_last_error(c, 998u, fault);
        if (rc) return rc;
        c->eax = 0;
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

    GuestCursorSnapshot snapshot = guest_cursor_get_snapshot();
    if (!snapshot.position_valid || !(snapshot.flags & GUEST_CURSOR_FLAG_AVAILABLE)) {
        return 0;
    }

    write32(dst, (uint32_t)snapshot.coords.x);
    write32((uint8_t *)dst + 4, (uint32_t)snapshot.coords.y);
    c->eax = 1;
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

/*
 * Win32 USER32!SetCursorPos(int x, int y)
 * It only updates an already available cursor or an explicit test fixture.
 * It cannot manufacture a live cursor on a headless/inactive host.
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
    int32_t x = (int32_t)read32(frame + 4);
    int32_t y = (int32_t)read32(frame + 8);

    if (g_synthetic_state.active) {
        if (!(g_synthetic_state.flags & GUEST_CURSOR_FLAG_AVAILABLE)) return 0;
        g_synthetic_state.coords = (GuestCursorCoords){x, y};
    } else {
        pthread_mutex_lock(&g_cursor_mutex);
        if (!g_cursor_state.position_valid ||
            !(g_cursor_state.flags & GUEST_CURSOR_FLAG_AVAILABLE)) {
            pthread_mutex_unlock(&g_cursor_mutex);
            return 0;
        }
        store_position_locked(x, y);
        pthread_mutex_unlock(&g_cursor_mutex);
    }

    c->eax = 1;
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

    int32_t count;
    if (g_synthetic_state.active) {
        if (b_show) {
            if (g_synthetic_state.display_count < INT32_MAX) g_synthetic_state.display_count++;
        } else {
            if (g_synthetic_state.display_count > INT32_MIN) g_synthetic_state.display_count--;
        }
        if (g_synthetic_state.display_count >= 0) g_synthetic_state.flags |= GUEST_CURSOR_FLAG_VISIBLE;
        else g_synthetic_state.flags &= ~GUEST_CURSOR_FLAG_VISIBLE;
        count = g_synthetic_state.display_count;
    } else {
        pthread_mutex_lock(&g_cursor_mutex);
        if (b_show) {
            if (g_cursor_state.display_count < INT32_MAX) g_cursor_state.display_count++;
        } else {
            if (g_cursor_state.display_count > INT32_MIN) g_cursor_state.display_count--;
        }
        if (g_cursor_state.display_count >= 0) g_cursor_state.flags |= GUEST_CURSOR_FLAG_VISIBLE;
        else g_cursor_state.flags &= ~GUEST_CURSOR_FLAG_VISIBLE;
        count = g_cursor_state.display_count;
        pthread_mutex_unlock(&g_cursor_mutex);
    }

    c->eax = (uint32_t)count;
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

void metal_get_cursor(int *x, int *y) {
    GuestCursorSnapshot snapshot = guest_cursor_get_snapshot();
    bool available = snapshot.position_valid &&
                     (snapshot.flags & GUEST_CURSOR_FLAG_AVAILABLE) != 0;
    if (x) *x = available ? snapshot.coords.x : 0;
    if (y) *y = available ? snapshot.coords.y : 0;
}

/*
 * DirectInput mouse state layouts:
 *   16 bytes: LONG x, LONG y, LONG z, BYTE buttons[4]
 *   20 bytes: LONG x, LONG y, LONG z, BYTE buttons[8]
 * Unsupported intermediate sizes are left untouched; larger buffers receive
 * the 20-byte state while trailing caller bytes remain unchanged.
 */
void metal_fill_mouse(unsigned char *dst, unsigned int n) {
    const unsigned int state_size = (n == 16u) ? 16u : ((n >= 20u) ? 20u : 0u);
    if (!dst || !state_size) return;

    int32_t dx;
    int32_t dy;
    uint32_t flags;
    if (g_synthetic_state.active) {
        dx = g_synthetic_state.mouse_dx;
        dy = g_synthetic_state.mouse_dy;
        g_synthetic_state.mouse_dx = 0;
        g_synthetic_state.mouse_dy = 0;
        flags = g_synthetic_state.flags;
    } else {
        pthread_mutex_lock(&g_cursor_mutex);
        dx = g_cursor_state.mouse_dx;
        dy = g_cursor_state.mouse_dy;
        g_cursor_state.mouse_dx = 0;
        g_cursor_state.mouse_dy = 0;
        flags = g_cursor_state.flags;
        pthread_mutex_unlock(&g_cursor_mutex);
    }

    const int32_t dz = 0;
    memcpy(dst, &dx, sizeof(dx));
    memcpy(dst + 4, &dy, sizeof(dy));
    memcpy(dst + 8, &dz, sizeof(dz));
    const unsigned int button_count = (state_size - 12u < 8u) ? state_size - 12u : 8u;
    memset(dst + 12, 0, button_count);
    if (button_count && (flags & GUEST_CURSOR_FLAG_DOWN)) dst[12] = 0x80;
}

void metal_mouse_add(int dx, int dy) {
    if (g_synthetic_state.active) {
        g_synthetic_state.mouse_dx = saturating_add_i32(g_synthetic_state.mouse_dx, dx);
        g_synthetic_state.mouse_dy = saturating_add_i32(g_synthetic_state.mouse_dy, dy);
        return;
    }
    pthread_mutex_lock(&g_cursor_mutex);
    g_cursor_state.mouse_dx = saturating_add_i32(g_cursor_state.mouse_dx, dx);
    g_cursor_state.mouse_dy = saturating_add_i32(g_cursor_state.mouse_dy, dy);
    pthread_mutex_unlock(&g_cursor_mutex);
}
