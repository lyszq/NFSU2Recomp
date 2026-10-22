#ifndef NFSU2_FILEIO_H
#define NFSU2_FILEIO_H

#include <stdint.h>

#define FILEIO_CASE_CACHE_CAPACITY 64u

typedef struct FileioPerfSnapshot {
    uint64_t case_cache_hits;
    uint64_t directory_scans;
    uint64_t cache_invalidations;
    uint64_t read_calls;
    uint64_t read_bytes;
} FileioPerfSnapshot;

/* Cumulative thread-safe counters for optional host-side performance logs.
 * cache_invalidations counts cached entries removed by mutations or root
 * changes; read_calls counts successful ReadFile dispatches. */
void fileio_perf_snapshot(FileioPerfSnapshot *snapshot);

#endif
