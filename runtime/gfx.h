/* com.c (guest tarafi) ile metal.m (cizim tarafi) arasindaki ortak kose bicimi.
 * Kose shader'i CPU'da calistirildigi icin buraya gelen konumlar KIRPMA
 * UZAYINDA (clip space) olur; perspektif bolmesini rasterlestirici yapar. */
#ifndef GFX_H
#define GFX_H
#include <stdint.h>
/* DIKKAT: doku koordinatlari asama basina DORT bilesen tasir.
 * Onceden yalnizca .xy tasiniyordu; oysa oyunun kose gölgelendiricileri
 * PROJEKSIYONLU koordinat uretiyor (olculdu: oT1.x/y/z = dot(v0, c4..c6),
 * oT1.w = r0.x).  z/w atilinca yol/araba yansimalari cizgi cizgi ve
 * karanlik cikiyordu. */
typedef struct {
    float x, y, z, w;      /* kirpma uzayi */
    float r, g, b, a;      /* oD0 - diffuse */
    float r1,g1,b1,a1;     /* oD1 - specular */
    float t[4][4];         /* oT0..oT3, tam dort bilesen */
} TVert;

void metal_draw_tv(const TVert *tv, unsigned nverts, unsigned prim, unsigned tex);
/* Main render-thread only: snapshots cumulative PSO lookup counters. */
void metal_pipeline_cache_snapshot(uint64_t *lookups, uint64_t *hits,
                                   uint64_t *probes, uint64_t *compiled_ns,
                                   unsigned *entries);

/* Lightweight cumulative renderer timings for the periodic runtime log.
 * Frame intervals are commit-to-commit and include app lifecycle gaps;
 * guest_present_interval_max_us is the max interval between metal_present calls. */
typedef struct {
    uint64_t vs_library_count, vs_library_ns;
    uint64_t ps_library_count, ps_library_ns;
    uint64_t texture_upload_count, texture_upload_ns, texture_upload_bytes;
    uint64_t frame_interval_le_16667_us, frame_interval_le_33333_us;
    uint64_t frame_interval_le_66667_us, frame_interval_gt_66667_us;
    uint64_t frame_interval_max_us;
    uint64_t guest_present_interval_max_us;
    uint64_t next_drawable_ns, encode_ns, guest_present_wait_ns;
    uint64_t frames_dropped, gpu_ring_busy_skips;
    /* Main encoder only, excluding fused postprocess/helper encoders.
     * CPU includes fixed-function draws. Published in batches per frame. */
    uint64_t main_gpu_vs_draws, main_cpu_vs_draws;
    uint64_t frames_committed; /* CPU command-buffer commits, not display proof. */
} MetalRuntimePerfSnapshot;
void metal_runtime_perf_snapshot(MetalRuntimePerfSnapshot *snapshot);
#endif
