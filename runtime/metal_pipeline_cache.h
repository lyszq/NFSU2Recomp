#ifndef NFS_METAL_PIPELINE_CACHE_H
#define NFS_METAL_PIPELINE_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    NFS_PIPELINE_CACHE_FULL = 0,
    NFS_PIPELINE_CACHE_INSERTED = 1,
    NFS_PIPELINE_CACHE_DUPLICATE = 2
};

/* Finalizer for a 64-bit key. Pipeline keys pack fields into fixed bit ranges,
 * so mix the full key before masking it to a power-of-two table. */
static inline uint64_t nfs_pipeline_cache_hash(uint64_t key){
    key ^= key >> 30;
    key *= UINT64_C(0xbf58476d1ce4e5b9);
    key ^= key >> 27;
    key *= UINT64_C(0x94d049bb133111eb);
    key ^= key >> 31;
    return key;
}

static inline int nfs_pipeline_cache_capacity_valid(size_t capacity){
    return capacity && !(capacity & (capacity - 1u));
}

static inline size_t nfs_pipeline_cache_bucket(uint64_t key, size_t capacity){
    return nfs_pipeline_cache_capacity_valid(capacity)
         ? (size_t)(nfs_pipeline_cache_hash(key) & (uint64_t)(capacity - 1u))
         : 0u;
}

static inline void nfs_pipeline_cache_clear(uint16_t *slots, size_t capacity){
    if (slots && capacity) memset(slots, 0, capacity * sizeof(*slots));
}

/* Entries are dense. Each entry's first member is its uint64_t key; stride
 * locates that member while allowing the caller to keep its own value beside
 * the key. A zero slot is empty; nonzero slots store dense index + 1. */
static inline int nfs_pipeline_cache_read_key(const void *entries,
                                               size_t stride,
                                               size_t entry_count,
                                               uint16_t index_plus_one,
                                               uint64_t *key){
    if (!entries || !key || stride < sizeof(*key) || !index_plus_one ||
        (size_t)index_plus_one > entry_count)
        return 0;
    size_t index = (size_t)index_plus_one - 1u;
    if (index > SIZE_MAX / stride) return 0;
    size_t offset = index * stride;
    if (offset > SIZE_MAX - sizeof(*key)) return 0;
    memcpy(key, (const unsigned char *)entries + offset, sizeof(*key));
    return 1;
}

static inline uint16_t nfs_pipeline_cache_find(const uint16_t *slots,
                                                size_t capacity,
                                                const void *entries,
                                                size_t stride,
                                                size_t entry_count,
                                                uint64_t key,
                                                size_t *probe_count,
                                                size_t *key_comparison_count){
    size_t probes = 0, comparisons = 0;
    uint16_t found = 0;
    if (slots && entries && stride >= sizeof(uint64_t) &&
        nfs_pipeline_cache_capacity_valid(capacity)){
        size_t slot = nfs_pipeline_cache_bucket(key, capacity);
        for (; probes < capacity; ++probes){
            uint16_t index_plus_one = slots[slot];
            if (!index_plus_one){
                ++probes; /* Include the empty slot that ended the search. */
                break;
            }
            uint64_t stored_key;
            if (nfs_pipeline_cache_read_key(entries, stride, entry_count,
                                            index_plus_one, &stored_key)){
                ++comparisons;
                if (stored_key == key){ found = index_plus_one; ++probes; break; }
            }
            slot = (slot + 1u) & (capacity - 1u);
        }
    }
    if (probe_count) *probe_count = probes;
    if (key_comparison_count) *key_comparison_count = comparisons;
    return found;
}

/* Insert only after the caller has written the corresponding dense entry.
 * Searches and writes are bounded by capacity even if the table is full. */
static inline int nfs_pipeline_cache_insert(uint16_t *slots,
                                             size_t capacity,
                                             const void *entries,
                                             size_t stride,
                                             size_t entry_count,
                                             uint64_t key,
                                             uint16_t index_plus_one,
                                             uint16_t *existing_index_plus_one,
                                             size_t *probe_count,
                                             size_t *key_comparison_count){
    size_t probes = 0, comparisons = 0;
    int result = NFS_PIPELINE_CACHE_FULL;
    if (existing_index_plus_one) *existing_index_plus_one = 0;
    if (slots && entries && stride >= sizeof(uint64_t) && index_plus_one &&
        (size_t)index_plus_one <= entry_count &&
        nfs_pipeline_cache_capacity_valid(capacity)){
        size_t slot = nfs_pipeline_cache_bucket(key, capacity);
        for (; probes < capacity; ++probes){
            uint16_t occupied = slots[slot];
            if (!occupied){
                slots[slot] = index_plus_one;
                ++probes;
                result = NFS_PIPELINE_CACHE_INSERTED;
                break;
            }
            uint64_t stored_key;
            if (nfs_pipeline_cache_read_key(entries, stride, entry_count,
                                            occupied, &stored_key)){
                ++comparisons;
                if (stored_key == key){
                    if (existing_index_plus_one)
                        *existing_index_plus_one = occupied;
                    ++probes;
                    result = NFS_PIPELINE_CACHE_DUPLICATE;
                    break;
                }
            }
            slot = (slot + 1u) & (capacity - 1u);
        }
    }
    if (probe_count) *probe_count = probes;
    if (key_comparison_count) *key_comparison_count = comparisons;
    return result;
}

#endif
