/*
 * NFSU2 iOS Port - Metal Renderer Bridge Implementation
 *
 * Provides default/fallback weak implementations of Metal rendering hooks
 * so the iOS target links cleanly whether runtime/metal.m is compiled into
 * the binary or provided by a downstream rendering module.
 */

#include "NFSU2MetalBridge.h"
#include <stdio.h>
#include <stdint.h>

__attribute__((weak)) void metal_init(void) {
    fprintf(stderr, "metal: default metal_init invoked\n");
}

__attribute__((weak)) void metal_early_init(void) {
}

__attribute__((weak)) void metal_run_main_loop(void) {
}

__attribute__((weak)) void metal_set_layer(void *layer) {
    (void)layer;
    fprintf(stderr, "metal: default metal_set_layer attached\n");
}

__attribute__((weak)) void metal_init_ios(void *caMetalLayer) {
    metal_set_layer(caMetalLayer);
}

__attribute__((weak)) int metal_render_frame(void) {
    return 0;
}

__attribute__((weak)) void metal_frame_begin(void) {
}

__attribute__((weak)) void metal_frame_end(void) {
}

__attribute__((weak)) void metal_begin_frame(void) {
}

__attribute__((weak)) void metal_present(void) {
}

__attribute__((weak)) void metal_resize(unsigned int width, unsigned int height) {
    (void)width;
    (void)height;
}

__attribute__((weak)) void metal_native_size(unsigned int gw, unsigned int gh, unsigned int *ow, unsigned int *oh) {
    if (ow) *ow = gw;
    if (oh) *oh = gh;
}

__attribute__((weak)) void metal_view_size(unsigned int *ow, unsigned int *oh) {
    if (ow) *ow = 1280;
    if (oh) *oh = 720;
}

__attribute__((weak)) void metal_game_size(unsigned int *w, unsigned int *h) {
    if (w) *w = 640;
    if (h) *h = 480;
}

__attribute__((weak)) void metal_set_game_size(unsigned int w, unsigned int h) {
    (void)w;
    (void)h;
}

__attribute__((weak)) void metal_set_ui_aspect(float a) {
    (void)a;
}

__attribute__((weak)) int metal_window_ready(void) {
    return 1;
}

__attribute__((weak)) long metal_frames(void) {
    return 0;
}

__attribute__((weak)) long metal_tris(void) {
    return 0;
}

__attribute__((weak)) long metal_tex_created(void) {
    return 0;
}

__attribute__((weak)) long metal_tex_uploaded(void) {
    return 0;
}

__attribute__((weak)) long metal_frames_dropped(void) {
    return 0;
}

__attribute__((weak)) int metal_quit_requested(void) {
    return 0;
}

__attribute__((weak)) int metal_thermal_state(void) {
    return 0;
}

__attribute__((weak)) unsigned long long metal_wait_present_ns(void) {
    return 0;
}

__attribute__((weak)) void metal_fill_mouse(unsigned char *dst, unsigned int n) {
    (void)dst;
    (void)n;
}

__attribute__((weak)) void metal_get_cursor(int *x, int *y) {
    if (x) *x = 0;
    if (y) *y = 0;
}

__attribute__((weak)) void metal_mouse_add(int dx, int dy) {
    (void)dx;
    (void)dy;
}
