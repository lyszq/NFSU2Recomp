#include "../NFSU2iOS/Native/GuestSmoke.h"
#include <stdio.h>
int main(void) {
    char out[1024] = {0};
    int rc = nfs_guest_smoke_run(out, sizeof out);
    puts(out);
    return rc;
}
