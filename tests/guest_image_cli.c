/* Private workflow only: caller verifies the exact EXE hash before execution.
 * Logs metadata/diagnostics, never proprietary source or image contents. */
#include "../ios/NFSU2iOS/Native/GuestImageProbe.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    const size_t size = 4788224;
    uint8_t *exe = malloc(size);
    if (!exe) { fclose(f); return 2; }
    size_t read = fread(exe, 1, size, f);
    int extra = fgetc(f), error = ferror(f);
    fclose(f);
    if (read != size || extra != EOF || error) { free(exe); return 2; }
    char out[2048];
    int rc = nfs_guest_image_probe(exe, size, out, sizeof out);
    puts(out);
    if (!rc) { rc = nfs_guest_image_probe(exe, size, out, sizeof out); puts(out); }
    free(exe);
    return rc ? 1 : 0;
}
