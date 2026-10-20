/* Bounds-checked extraction of mem.c's preferred-base PE section loading.
 * Format reference: learn.microsoft.com/windows/win32/debug/pe-format */
#include "guest_pe.h"
#include "guest_memory.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static uint16_t u16(const uint8_t *p) {
    return (uint16_t)(p[0] | (uint16_t)p[1] << 8);
}
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static int fits(uint64_t offset, uint64_t size, uint64_t length) {
    return offset <= length && size <= length - offset;
}
static int fail(char *out, size_t capacity, const char *phase, int error) {
    if (out && capacity) (void)snprintf(out, capacity, "FAIL | PE32 %s | error=%d", phase, error);
    return error;
}
int guest_pe_load(const void *source, size_t length, GuestPEImage *image,
                  char *out, size_t capacity) {
    if (!image) return fail(out, capacity, "missing output", EINVAL);
    memset(image, 0, sizeof *image);
    if (out && capacity) out[0] = '\0';
    if (g_mem) return fail(out, capacity, "runtime already active", EBUSY);
    const uint8_t *buf = source;
    if (!buf || length < 64 || u16(buf) != 0x5a4d)
        return fail(out, capacity, "DOS header", EINVAL);
    const uint64_t nt = u32(buf + 0x3c);
    if (nt < 64 || !fits(nt, 24, length) || u32(buf + nt) != 0x4550)
        return fail(out, capacity, "NT header", EINVAL);
    const uint8_t *coff = buf + nt;
    const unsigned sections = u16(coff + 6), opt_size = u16(coff + 20);
    const uint64_t opt_offset = nt + 24, table = opt_offset + opt_size;
    if (u16(coff + 4) != 0x14c || !sections || sections > 96 ||
        opt_size < 96 || !fits(opt_offset, opt_size, length) ||
        !fits(table, sections * 40u, length))
        return fail(out, capacity, "i386 optional header/section table", EINVAL);
    const uint8_t *opt = buf + opt_offset;
    if (u16(opt) != 0x10b) return fail(out, capacity, "requires PE32", ENOTSUP);
    const uint32_t base = u32(opt + 28), size = u32(opt + 56);
    const uint32_t headers = u32(opt + 60), entry = u32(opt + 16);
    const uint32_t directories = u32(opt + 92);
    if (!base || base % GUEST_MEMORY_GRANULE || !size || size > 64u * 1024u * 1024u ||
        !fits(base, size, GUEST_MEMORY_SIZE) || !headers || headers > size ||
        headers > length || table + sections * 40u > headers || entry >= size ||
        directories > (opt_size - 96u) / 8u)
        return fail(out, capacity, "image/header/directory bounds", EINVAL);
    uint32_t resource = 0, resource_size = 0;
    if (directories > 2) {
        resource = u32(opt + 112); resource_size = u32(opt + 116);
        if ((!resource != !resource_size) || !fits(resource, resource_size, size))
            return fail(out, capacity, "resource bounds", EINVAL);
    }
    int entry_backed = 0;
    for (unsigned i = 0; i < sections; ++i) {
        const uint8_t *s = buf + table + i * 40u;
        uint32_t vs = u32(s + 8), va = u32(s + 12);
        const uint32_t raw = u32(s + 16), offset = u32(s + 20);
        if (!vs) vs = raw;
        if (!fits(va, vs, size) || (vs && va < headers) ||
            (raw && (offset < headers || !fits(offset, raw, length))))
            return fail(out, capacity, "section bounds", EINVAL);
        for (unsigned j = 0; j < i; ++j) {
            const uint8_t *other = buf + table + j * 40u;
            uint32_t ov = u32(other + 8), oa = u32(other + 12);
            if (!ov) ov = u32(other + 16);
            if (vs && ov && (uint64_t)va < (uint64_t)oa + ov &&
                (uint64_t)oa < (uint64_t)va + vs)
                return fail(out, capacity, "overlapping sections", EINVAL);
        }
        uint32_t copied = raw < vs ? raw : vs;
        if (entry >= va && (uint64_t)entry < (uint64_t)va + copied &&
            (u32(s + 36) & 0x20000000u)) entry_backed = 1;
    }
    if (!entry_backed) return fail(out, capacity, "entry is not file-backed code", EINVAL);
    int rc = guest_memory_init();
    if (rc) return fail(out, capacity, "reserve guest VM", rc);
    rc = guest_memory_commit(base, size);
    if (rc) {
        int cleanup = guest_memory_shutdown();
        return fail(out, capacity, cleanup ? "commit + cleanup failed" : "commit image", cleanup ? cleanup : rc);
    }
    uint8_t *mapped = guest_memory_pointer(base, size, 1);
    /* The owner has exclusive lifecycle access for this entire operation. */
    if (!mapped) {
        rc = guest_memory_shutdown();
        return fail(out, capacity, "checked translation", rc ? rc : EFAULT);
    }
    memset(mapped, 0, size);
    memcpy(mapped, buf, headers);
    for (unsigned i = 0; i < sections; ++i) {
        const uint8_t *s = buf + table + i * 40u;
        uint32_t vs = u32(s + 8), raw = u32(s + 16);
        if (!vs) vs = raw;
        uint32_t copied = raw < vs ? raw : vs;
        if (copied) memcpy(mapped + u32(s + 12), buf + u32(s + 20), copied);
    }
    image->image_base = base; image->image_size = size;
    image->entry_point = base + entry;
    image->resource_address = resource ? base + resource : 0;
    image->resource_size = resource_size; image->section_count = sections;
    if (out && capacity) (void)snprintf(out, capacity,
        "PASS | PE32 image loaded | base=%08x size=%u entry=%08x sections=%u | no guest execution",
        base, size, image->entry_point, sections);
    return 0;
}
