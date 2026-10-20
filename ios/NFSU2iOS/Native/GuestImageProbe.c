#include "GuestImageProbe.h"
#include "../../../runtime/guest_pe.h"
#include "../../../runtime/guest_memory.h"
#include <errno.h>
#include <stdio.h>
#ifdef NFS_PRIVATE_PROBE
/* This symbol MUST be supplied by privately generated, native compiled C.
 * There is deliberately no weak/dummy implementation or fallback success. */
int nfs_private_lifted_probe(char *out, size_t capacity);
#ifdef NFS_PRIVATE_STARTUP
int nfs_private_startup_probe(const GuestPEImage *image, char *out, size_t capacity);
#endif
#endif

int nfs_guest_image_probe(const uint8_t *exe, size_t length, char *out, size_t capacity) {
    if (!out || !capacity) return EINVAL;
    out[0] = '\0';
    GuestPEImage image;
    int rc = guest_pe_load(exe, length, &image, out, capacity);
    if (rc) return rc;
    if (image.image_base != 0x00400000u || image.entry_point != 0x0075bcc7u) {
        rc = EINVAL;
        (void)snprintf(out, capacity, "FAIL | unexpected supported-image layout");
    } else {
#ifdef NFS_PRIVATE_PROBE
        rc = nfs_private_lifted_probe(out, capacity);
#ifdef NFS_PRIVATE_STARTUP
        if (!rc) rc = nfs_private_startup_probe(&image, out, capacity);
#endif
#else
        (void)snprintf(out, capacity,
            "PASS | verified EXE mapped into shared guest VM | base=%08x size=%u "
            "entry=%08x sections=%u | headers + sections + zero-fill | no game code executed",
            image.image_base, image.image_size, image.entry_point, image.section_count);
#endif
    }
    const int cleanup = guest_memory_shutdown();
    if (cleanup) {
        (void)snprintf(out, capacity, "FAIL | image VM cleanup | error=%d", cleanup);
        return cleanup;
    }
    return rc;
}
