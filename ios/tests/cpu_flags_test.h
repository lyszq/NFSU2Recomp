#ifndef NFSU2_IOS_CPU_FLAGS_TEST_H
#define NFSU2_IOS_CPU_FLAGS_TEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns zero when every CPU flag check passes. */
int nfs_cpu_flags_test(char *diagnostics, size_t diagnostics_capacity);

#ifdef __cplusplus
}
#endif

#endif
