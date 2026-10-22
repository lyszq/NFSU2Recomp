#include "metal_pipeline_cache.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)){ \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static int test_capacity_and_empty_lookup(void){
    uint64_t entries[4] = { UINT64_C(0x123456789abcdef0), 0, 0, 0 };
    uint16_t slots[8] = {0};
    size_t probes = 0, comparisons = 0;
    CHECK(nfs_pipeline_cache_capacity_valid(8));
    CHECK(!nfs_pipeline_cache_capacity_valid(0));
    CHECK(!nfs_pipeline_cache_capacity_valid(6));
    CHECK(nfs_pipeline_cache_find(slots, 8, entries, sizeof(entries[0]), 1,
                                  entries[0], &probes, &comparisons) == 0);
    CHECK(probes == 1 && comparisons == 0);
    return 1;
}

static int test_high_bits_and_duplicate_key(void){
    uint64_t entries[4] = {
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0x8123456789abcdef),
        UINT64_C(0xfedcba9876543210),
        0
    };
    uint16_t slots[8] = {0};
    uint16_t existing = 0;
    size_t probes = 0, comparisons = 0;
    CHECK(entries[0] != entries[1]);
    CHECK((entries[0] & UINT64_C(0x0000ffffffffffff)) ==
          (entries[1] & UINT64_C(0x0000ffffffffffff)));
    CHECK(nfs_pipeline_cache_insert(slots, 8, entries, sizeof(entries[0]), 1,
                                   entries[0], 1, &existing, &probes,
                                   &comparisons) == NFS_PIPELINE_CACHE_INSERTED);
    CHECK(nfs_pipeline_cache_insert(slots, 8, entries, sizeof(entries[0]), 2,
                                   entries[1], 2, &existing, &probes,
                                   &comparisons) == NFS_PIPELINE_CACHE_INSERTED);
    CHECK(nfs_pipeline_cache_find(slots, 8, entries, sizeof(entries[0]), 2,
                                  entries[0], NULL, NULL) == 1);
    CHECK(nfs_pipeline_cache_find(slots, 8, entries, sizeof(entries[0]), 2,
                                  entries[1], NULL, NULL) == 2);
    CHECK(nfs_pipeline_cache_insert(slots, 8, entries, sizeof(entries[0]), 3,
                                   entries[0], 3, &existing, NULL, NULL) ==
          NFS_PIPELINE_CACHE_DUPLICATE);
    CHECK(existing == 1);
    CHECK(nfs_pipeline_cache_find(slots, 8, entries, sizeof(entries[0]), 3,
                                  entries[0], NULL, NULL) == 1);
    return 1;
}

static int test_forced_collisions_and_missing_key(void){
    enum { CAPACITY = 8, COLLISIONS = 4 };
    uint64_t entries[COLLISIONS] = {0};
    uint16_t slots[CAPACITY] = {0};
    uint64_t collision_keys[COLLISIONS + 1];
    size_t count = 0, target = 0;
    uint64_t seed = 1;
    while (count < COLLISIONS + 1){
        uint64_t candidate = UINT64_C(0xf000000000000000) ^
                             (seed++ * UINT64_C(0x9e3779b97f4a7c15));
        size_t bucket = nfs_pipeline_cache_bucket(candidate, CAPACITY);
        if (!count) target = bucket;
        if (bucket != target) continue;
        int duplicate = 0;
        for (size_t i = 0; i < count; ++i)
            if (collision_keys[i] == candidate) duplicate = 1;
        if (!duplicate) collision_keys[count++] = candidate;
    }

    for (size_t i = 0; i < COLLISIONS; ++i){
        entries[i] = collision_keys[i];
        CHECK(nfs_pipeline_cache_insert(slots, CAPACITY, entries,
                                        sizeof(entries[0]), i + 1u,
                                        entries[i], (uint16_t)(i + 1u),
                                        NULL, NULL, NULL) ==
              NFS_PIPELINE_CACHE_INSERTED);
    }
    for (size_t i = 0; i < COLLISIONS; ++i)
        CHECK(nfs_pipeline_cache_find(slots, CAPACITY, entries,
                                      sizeof(entries[0]), COLLISIONS,
                                      collision_keys[i], NULL, NULL) == i + 1u);
    size_t probes = 0, comparisons = 0;
    CHECK(nfs_pipeline_cache_find(slots, CAPACITY, entries, sizeof(entries[0]),
                                  COLLISIONS, collision_keys[COLLISIONS],
                                  &probes, &comparisons) == 0);
    CHECK(probes == COLLISIONS + 1u && comparisons == COLLISIONS);
    return 1;
}

static int test_full_table_has_bounded_failure(void){
    enum { CAPACITY = 8 };
    uint64_t entries[CAPACITY + 1];
    uint16_t slots[CAPACITY] = {0};
    for (size_t i = 0; i < CAPACITY + 1u; ++i)
        entries[i] = UINT64_C(0x1000000000000000) + (uint64_t)i * 17u;
    for (size_t i = 0; i < CAPACITY; ++i)
        CHECK(nfs_pipeline_cache_insert(slots, CAPACITY, entries,
                                        sizeof(entries[0]), i + 1u,
                                        entries[i], (uint16_t)(i + 1u),
                                        NULL, NULL, NULL) ==
              NFS_PIPELINE_CACHE_INSERTED);

    size_t probes = 0, comparisons = 0;
    CHECK(nfs_pipeline_cache_find(slots, CAPACITY, entries, sizeof(entries[0]),
                                  CAPACITY, entries[CAPACITY], &probes,
                                  &comparisons) == 0);
    CHECK(probes == CAPACITY && comparisons == CAPACITY);
    CHECK(nfs_pipeline_cache_insert(slots, CAPACITY, entries,
                                   sizeof(entries[0]), CAPACITY + 1u,
                                   entries[CAPACITY], CAPACITY + 1u, NULL,
                                   &probes, &comparisons) ==
          NFS_PIPELINE_CACHE_FULL);
    CHECK(probes == CAPACITY);
    for (size_t i = 0; i < CAPACITY; ++i)
        CHECK(nfs_pipeline_cache_find(slots, CAPACITY, entries,
                                      sizeof(entries[0]), CAPACITY,
                                      entries[i], NULL, NULL) == i + 1u);
    return 1;
}

static int test_uint16_index_plus_one_limit(void){
    enum { MAX_ENTRIES = 2048, CAPACITY = 4096 };
    static uint64_t entries[MAX_ENTRIES];
    static uint16_t slots[CAPACITY];
    const uint16_t last_index_plus_one = UINT16_C(2048);
    entries[MAX_ENTRIES - 1u] = UINT64_C(0x8000000000001234);
    nfs_pipeline_cache_clear(slots, CAPACITY);
    CHECK(nfs_pipeline_cache_insert(slots, CAPACITY, entries,
                                    sizeof(entries[0]), MAX_ENTRIES,
                                    entries[MAX_ENTRIES - 1u],
                                    last_index_plus_one, NULL, NULL, NULL) ==
          NFS_PIPELINE_CACHE_INSERTED);
    CHECK(nfs_pipeline_cache_find(slots, CAPACITY, entries, sizeof(entries[0]),
                                  MAX_ENTRIES, entries[MAX_ENTRIES - 1u],
                                  NULL, NULL) == last_index_plus_one);
    return 1;
}

static uint64_t synthetic_pipeline_key(size_t i){
    return (uint64_t)(i & 0xfffffu) |
           ((uint64_t)((i * 37u) & 0xfffu) << 20) |
           ((uint64_t)((i * 71u) & 0xfffu) << 32) |
           ((uint64_t)(i & 1u) << 52) |
           ((uint64_t)(i & 3u) << 53);
}

static int benchmark_scan_comparisons_vs_hash_probes(void){
    enum { MAX_ENTRIES = 1024, MAX_CAPACITY = MAX_ENTRIES * 2,
           SYNTHETIC_DRAWS = 1350 };
    static uint64_t entries[MAX_ENTRIES];
    static uint16_t slots[MAX_CAPACITY];
    static const size_t sizes[] = {64, 256, 512, 1024};

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s){
        size_t count = sizes[s], capacity = count * 2u;
        size_t linear_hits = 0, hash_hit_probes = 0, hash_hit_comparisons = 0;
        size_t linear_misses = 0, hash_miss_probes = 0, hash_miss_comparisons = 0;
        nfs_pipeline_cache_clear(slots, capacity);
        for (size_t i = 0; i < count; ++i) entries[i] = synthetic_pipeline_key(i);
        for (size_t i = 0; i < count; ++i)
            CHECK(nfs_pipeline_cache_insert(slots, capacity, entries,
                                            sizeof(entries[0]), count,
                                            entries[i], (uint16_t)(i + 1u),
                                            NULL, NULL, NULL) ==
                  NFS_PIPELINE_CACHE_INSERTED);

        for (size_t draw = 0; draw < SYNTHETIC_DRAWS; ++draw){
            size_t wanted = (draw * 137u) % count;
            size_t linear_index = 0;
            for (; linear_index < count; ++linear_index){
                ++linear_hits;
                if (entries[linear_index] == entries[wanted]) break;
            }
            size_t probes = 0, comparisons = 0;
            uint16_t found = nfs_pipeline_cache_find(slots, capacity, entries,
                                                      sizeof(entries[0]), count,
                                                      entries[wanted], &probes,
                                                      &comparisons);
            CHECK(linear_index < count && found == wanted + 1u);
            hash_hit_probes += probes;
            hash_hit_comparisons += comparisons;
        }
        for (size_t draw = 0; draw < SYNTHETIC_DRAWS; ++draw){
            uint64_t missing = entries[(draw * 137u) % count] ^
                               UINT64_C(0x8000000000000000);
            linear_misses += count;
            size_t probes = 0, comparisons = 0;
            CHECK(nfs_pipeline_cache_find(slots, capacity, entries,
                                          sizeof(entries[0]), count, missing,
                                          &probes, &comparisons) == 0);
            hash_miss_probes += probes;
            hash_miss_comparisons += comparisons;
        }
        printf("N=%zu cap=%zu draws=%d hits: linear comparisons=%zu, hash probes=%zu, key comparisons=%zu; "
               "misses: linear comparisons=%zu, hash probes=%zu, key comparisons=%zu\n",
               count, capacity, SYNTHETIC_DRAWS, linear_hits, hash_hit_probes,
               hash_hit_comparisons, linear_misses, hash_miss_probes,
               hash_miss_comparisons);
    }
    return 1;
}

int main(void){
    if (!test_capacity_and_empty_lookup()) return 1;
    if (!test_high_bits_and_duplicate_key()) return 1;
    if (!test_forced_collisions_and_missing_key()) return 1;
    if (!test_full_table_has_bounded_failure()) return 1;
    if (!test_uint16_index_plus_one_limit()) return 1;
    if (!benchmark_scan_comparisons_vs_hash_probes()) return 1;
    puts("PASS: Metal pipeline cache collisions, full-key equality, capacity and operation counts");
    return 0;
}
