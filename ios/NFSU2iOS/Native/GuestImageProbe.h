#ifndef NFSU2_GUEST_IMAGE_PROBE_H
#define NFSU2_GUEST_IMAGE_PROBE_H
#include <stddef.h>
#include <stdint.h>
/* Caller must authenticate the complete immutable EXE by size and SHA-256.
 * Runs only while other guest probes/game execution are idle. Releases its VM.
 */
int nfs_guest_image_probe(const uint8_t *exe, size_t length, char *out, size_t capacity);
#endif
