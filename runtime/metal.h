/*
 * NFSU2 Metal Renderer Interface
 *
 * Provides shared graphics pipeline declarations for macOS and iOS:
 * D3D9 bridge, lifecycle initialization, surface attachment, and frame rendering.
 */
#ifndef RUNTIME_METAL_H
#define RUNTIME_METAL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Metal Engine Lifecycle --- */
void metal_init(void);
void metal_early_init(void);
void metal_run_main_loop(void);

/* --- iOS CAMetalLayer Attachment --- */
void metal_set_layer(void *layer);
void metal_init_ios(void *caMetalLayer);

/* --- Frame Presentation & Lifecycle --- */
int  metal_render_frame(void);
void metal_frame_begin(void);
void metal_frame_end(void);
void metal_begin_frame(void);
void metal_present(void);

/* --- Geometry & Windowing --- */
void metal_resize(unsigned int width, unsigned int height);
void metal_native_size(unsigned int gw, unsigned int gh, unsigned int *ow, unsigned int *oh);
void metal_view_size(unsigned int *ow, unsigned int *oh);
void metal_game_size(unsigned int *w, unsigned int *h);
void metal_set_game_size(unsigned int w, unsigned int h);
void metal_set_ui_aspect(float a);

/* --- Statistics & State Queries --- */
int  metal_available(void);
int  metal_window_ready(void);
long metal_frames(void);
long metal_tris(void);
long metal_tex_created(void);
long metal_tex_uploaded(void);
long metal_frames_dropped(void);
int  metal_quit_requested(void);
int  metal_thermal_state(void);
unsigned long long metal_wait_present_ns(void);

/* --- DirectInput Keyboard & Mouse Emulation --- */
void metal_fill_keyboard(unsigned char *dst, unsigned int n);
void metal_fill_mouse(unsigned char *dst, unsigned int n);
void metal_get_cursor(int *x, int *y);
void metal_mouse_add(int dx, int dy);

#ifdef __cplusplus
}
#endif

#endif /* RUNTIME_METAL_H */
