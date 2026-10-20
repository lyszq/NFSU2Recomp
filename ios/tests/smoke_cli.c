#include "../NFSU2iOS/Native/GuestSmoke.h"
#include <stdio.h>
#include "cpu_flags_test.h"
int main(void) {
    char out[1024] = {0};
    int rc = nfs_cpu_flags_test(out, sizeof out);
    puts(out);
    if (rc) return rc;
    rc = nfs_guest_smoke_run(out, sizeof out);
    puts(out);
    if (rc) return rc;
    /* A second run must reserve fresh memory and reset all bookkeeping. */
    rc = nfs_guest_smoke_run(out, sizeof out);
    puts(out);
    return rc;
}
