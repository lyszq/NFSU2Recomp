#ifndef NFSU2_GUEST_PE_H
#define NFSU2_GUEST_PE_H
#include <stddef.h>
#include <stdint.h>

typedef struct GuestPEImage {
    uint32_t image_base, image_size, entry_point;
    uint32_t resource_address, resource_size, section_count;
} GuestPEImage;

/* Map a validated PE32/i386 image at its preferred guest address. Requires an
 * idle guest runtime. Success owns the mapping until guest_memory_shutdown().
 * Error leaves no new mapping; malformed input is checked before allocation.
 * No import binding, relocations, TLS startup or guest execution is performed.
 * This loader is limited to 64 MiB images and 96 non-overlapping sections.
 * Source must remain immutable and outside the guest mapping during the call.
 */
int guest_pe_load(const void *source, size_t length, GuestPEImage *image,
                  char *diagnostic, size_t capacity);
#endif
