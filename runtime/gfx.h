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
#endif
