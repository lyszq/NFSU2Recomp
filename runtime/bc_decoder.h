#ifndef NFS_BC_DECODER_H
#define NFS_BC_DECODER_H

/* Minimal CPU fallback for D3D9 BC textures on Metal devices without BC
 * texture compression. The output byte order is BGRA8 to match
 * MTLPixelFormatBGRA8Unorm. This decoder is deliberately independent of
 * Apple APIs so its block and edge handling can be covered by native tests. */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define NFS_D3DFMT_DXT1 UINT32_C(0x31545844)
#define NFS_D3DFMT_DXT3 UINT32_C(0x33545844)
#define NFS_D3DFMT_DXT5 UINT32_C(0x35545844)

static inline uint16_t nfs_bc_read_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t nfs_bc_read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint8_t nfs_bc_expand5(unsigned v) {
    return (uint8_t)((v << 3) | (v >> 2));
}

static inline uint8_t nfs_bc_expand6(unsigned v) {
    return (uint8_t)((v << 2) | (v >> 4));
}

static inline void nfs_bc_decode_colors(const uint8_t *block, int force_four,
                                        uint8_t colors[4][4]) {
    uint16_t c0 = nfs_bc_read_u16(block);
    uint16_t c1 = nfs_bc_read_u16(block + 2);
    unsigned r0 = nfs_bc_expand5((c0 >> 11) & 31u);
    unsigned g0 = nfs_bc_expand6((c0 >> 5) & 63u);
    unsigned b0 = nfs_bc_expand5(c0 & 31u);
    unsigned r1 = nfs_bc_expand5((c1 >> 11) & 31u);
    unsigned g1 = nfs_bc_expand6((c1 >> 5) & 63u);
    unsigned b1 = nfs_bc_expand5(c1 & 31u);

    colors[0][0] = (uint8_t)b0; colors[0][1] = (uint8_t)g0;
    colors[0][2] = (uint8_t)r0; colors[0][3] = 255;
    colors[1][0] = (uint8_t)b1; colors[1][1] = (uint8_t)g1;
    colors[1][2] = (uint8_t)r1; colors[1][3] = 255;
    if (force_four || c0 > c1) {
        colors[2][0] = (uint8_t)((2u * b0 + b1) / 3u);
        colors[2][1] = (uint8_t)((2u * g0 + g1) / 3u);
        colors[2][2] = (uint8_t)((2u * r0 + r1) / 3u);
        colors[2][3] = 255;
        colors[3][0] = (uint8_t)((b0 + 2u * b1) / 3u);
        colors[3][1] = (uint8_t)((g0 + 2u * g1) / 3u);
        colors[3][2] = (uint8_t)((r0 + 2u * r1) / 3u);
        colors[3][3] = 255;
    } else {
        colors[2][0] = (uint8_t)((b0 + b1) / 2u);
        colors[2][1] = (uint8_t)((g0 + g1) / 2u);
        colors[2][2] = (uint8_t)((r0 + r1) / 2u);
        colors[2][3] = 255;
        colors[3][0] = 0; colors[3][1] = 0;
        colors[3][2] = 0; colors[3][3] = 0;
    }

}

static inline void nfs_bc_decode_color_pixels(const uint8_t *block, int force_four,
                                              uint8_t pixels[16][4]) {
    uint8_t colors[4][4];
    uint32_t selectors = nfs_bc_read_u32(block + 4);
    nfs_bc_decode_colors(block, force_four, colors);
    for (unsigned i = 0; i < 16; ++i) {
        unsigned index = (selectors >> (i * 2u)) & 3u;
        pixels[i][0] = colors[index][0];
        pixels[i][1] = colors[index][1];
        pixels[i][2] = colors[index][2];
        pixels[i][3] = colors[index][3];
    }
}

static inline void nfs_bc_decode_alpha_dxt5(const uint8_t *block,
                                            uint8_t alpha[16]) {
    uint8_t a[8];
    uint64_t selectors = 0;
    a[0] = block[0]; a[1] = block[1];
    if (a[0] > a[1]) {
        for (unsigned i = 1; i <= 6; ++i)
            a[i + 1] = (uint8_t)(((7u - i) * a[0] + i * a[1]) / 7u);
    } else {
        for (unsigned i = 1; i <= 4; ++i)
            a[i + 1] = (uint8_t)(((5u - i) * a[0] + i * a[1]) / 5u);
        a[6] = 0;
        a[7] = 255;
    }
    for (unsigned i = 0; i < 6; ++i)
        selectors |= (uint64_t)block[2 + i] << (i * 8u);
    for (unsigned i = 0; i < 16; ++i)
        alpha[i] = a[(selectors >> (i * 3u)) & 7u];
}

/* Decode one tightly or row-padded DXT1/3/5 image to an allocated BGRA8
 * buffer. source_pitch is the compressed bytes per block row, as reported by
 * the guest lock; dimensions are the current mip dimensions. The caller owns
 * *out_pixels and must free it. */
static inline int nfs_bc_decode_bgra(uint32_t format, const void *source,
                                     size_t source_pitch, uint32_t width,
                                     uint32_t height, uint8_t **out_pixels,
                                     size_t *out_pitch) {
    if (out_pixels) *out_pixels = NULL;
    if (out_pitch) *out_pitch = 0;
    if (!out_pixels || !out_pitch || !source || !width || !height ||
        width > 16384u || height > 16384u)
        return 0;

    size_t block_bytes;
    if (format == NFS_D3DFMT_DXT1) block_bytes = 8;
    else if (format == NFS_D3DFMT_DXT3 || format == NFS_D3DFMT_DXT5)
        block_bytes = 16;
    else return 0;

    size_t blocks_x = ((size_t)width + 3u) / 4u;
    size_t blocks_y = ((size_t)height + 3u) / 4u;
    if (blocks_x > SIZE_MAX / block_bytes) return 0;
    size_t min_source_pitch = blocks_x * block_bytes;
    if (source_pitch < min_source_pitch ||
        (blocks_y && source_pitch > SIZE_MAX / blocks_y) ||
        (size_t)width > SIZE_MAX / 4u)
        return 0;
    size_t destination_pitch = (size_t)width * 4u;
    if ((size_t)height > SIZE_MAX / destination_pitch) return 0;
    uint8_t *destination = (uint8_t *)malloc(destination_pitch * height);
    if (!destination) return 0;

    const uint8_t *src = (const uint8_t *)source;
    for (size_t by = 0; by < blocks_y; ++by) {
        const uint8_t *src_row = src + by * source_pitch;
        for (size_t bx = 0; bx < blocks_x; ++bx) {
            const uint8_t *block = src_row + bx * block_bytes;
            uint8_t colors[16][4];
            uint8_t alpha[16];
            const uint8_t *color_block = block;
            int force_four = format != NFS_D3DFMT_DXT1;

            if (format == NFS_D3DFMT_DXT3) {
                color_block += 8;
                uint64_t alpha_bits = 0;
                for (unsigned i = 0; i < 8; ++i)
                    alpha_bits |= (uint64_t)block[i] << (i * 8u);
                for (unsigned i = 0; i < 16; ++i)
                    alpha[i] = (uint8_t)(((alpha_bits >> (i * 4u)) & 15u) * 17u);
            } else if (format == NFS_D3DFMT_DXT5) {
                color_block += 8;
                nfs_bc_decode_alpha_dxt5(block, alpha);
            }

            nfs_bc_decode_color_pixels(color_block, force_four, colors);
            for (unsigned py = 0; py < 4; ++py) {
                size_t y = by * 4u + py;
                if (y >= height) continue;
                for (unsigned px = 0; px < 4; ++px) {
                    size_t x = bx * 4u + px;
                    if (x >= width) continue;
                    unsigned i = py * 4u + px;
                    uint8_t *pixel = destination + y * destination_pitch + x * 4u;
                    pixel[0] = colors[i][0];
                    pixel[1] = colors[i][1];
                    pixel[2] = colors[i][2];
                    pixel[3] = format == NFS_D3DFMT_DXT1 ? colors[i][3] : alpha[i];
                }
            }
        }
    }
    *out_pixels = destination;
    *out_pitch = destination_pitch;
    return 1;
}

#endif
