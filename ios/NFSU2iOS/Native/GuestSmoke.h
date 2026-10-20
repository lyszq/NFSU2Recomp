#ifndef NFSU2_IOS_GUEST_SMOKE_H
#define NFSU2_IOS_GUEST_SMOKE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 0 means every test passed; nonzero means inspect the diagnostic buffer. */
int nfs_guest_smoke_run(char *diagnostics, size_t diagnostics_capacity);

#ifdef __cplusplus
}
#endif
#endif
