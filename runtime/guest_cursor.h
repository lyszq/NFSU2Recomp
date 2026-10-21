/*
 * NFSU2 Guest Runtime - Synchronized cursor and pointer state.
 *
 * Host input may arrive on a UI thread while guest calls read the pointer on
 * the runtime thread. One mutex protects the live coordinates, availability,
 * viewport mapping, display count, and relative mouse state as coherent data.
 */

#ifndef NFSU2_GUEST_CURSOR_H
#define NFSU2_GUEST_CURSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "cpu.h"
#include "guest_execution.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cursor availability and state flags. */
#define GUEST_CURSOR_FLAG_AVAILABLE   (1u << 0)  /* Host cursor/touch input active */
#define GUEST_CURSOR_FLAG_VISIBLE     (1u << 1)  /* Win32 ShowCursor display count >= 0 */
#define GUEST_CURSOR_FLAG_DOWN        (1u << 2)  /* Primary button / touch is down */
#define GUEST_CURSOR_FLAG_SYNTHETIC   (1u << 3)  /* Reserved for explicit test fixtures */

typedef enum GuestCursorScalingMode {
    GUEST_CURSOR_SCALE_FIT = 0,     /* Maintain aspect ratio with letterbox/pillarbox */
    GUEST_CURSOR_SCALE_STRETCH = 1  /* Fill entire viewport */
} GuestCursorScalingMode;

typedef struct GuestCursorCoords {
    int32_t x;
    int32_t y;
} GuestCursorCoords;

/* A coherent point-in-time view of live cursor state. */
typedef struct GuestCursorSnapshot {
    GuestCursorCoords coords;
    uint32_t flags;
    bool position_valid;
} GuestCursorSnapshot;

/* Module Lifecycle */
void guest_cursor_init(void);
void guest_cursor_reset(void);

/* Viewport Configuration (for host-to-game coordinate conversion). */
void guest_cursor_set_viewport(uint32_t viewport_w, uint32_t viewport_h,
                               uint32_t game_w, uint32_t game_h,
                               GuestCursorScalingMode mode);

/* Coordinate Translation Helpers. */
void guest_cursor_host_to_game(float host_x, float host_y, int32_t *game_x, int32_t *game_y);
void guest_cursor_game_to_host(int32_t game_x, int32_t game_y, float *host_x, float *host_y);

/* Host / UI Thread Ingress. */
void guest_cursor_set_host_pos(float host_x, float host_y, bool is_down);
void guest_cursor_set_available(bool available);

/* Current State Query. The snapshot getter keeps coordinates and flags coherent. */
GuestCursorSnapshot guest_cursor_get_snapshot(void);
GuestCursorCoords    guest_cursor_get_coords(void);
uint32_t             guest_cursor_get_flags(void);
int32_t              guest_cursor_get_display_count(void);

/* Per-thread synthetic test fixture, active only on the calling thread.
 * Fixture flags are returned exactly as supplied; they do not modify live state. */
void guest_cursor_inject_synthetic(int32_t x, int32_t y, uint32_t flags);
void guest_cursor_clear_synthetic(void);
bool guest_cursor_is_synthetic(void);

/* Guest Win32 USER32 Import Handlers (Invoked from guest_windows.c). */
int guest_user32_get_cursor_pos(CPU *c, const GuestImport *import, uint32_t *fault);
int guest_user32_set_cursor_pos(CPU *c, const GuestImport *import, uint32_t *fault);
int guest_user32_show_cursor(CPU *c, const GuestImport *import, uint32_t *fault);

/* DirectInput / Metal Bridge Mouse Emulation. */
void metal_fill_mouse(unsigned char *dst, unsigned int n);
void metal_get_cursor(int *x, int *y);
void metal_mouse_add(int dx, int dy);

#ifdef __cplusplus
}
#endif

#endif /* NFSU2_GUEST_CURSOR_H */
