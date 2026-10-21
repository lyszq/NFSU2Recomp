#include "guest_heap.h"
#include "guest_memory.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL guest heap line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int all_bytes_are(uint32_t address, uint32_t size, uint8_t expected) {
    const uint8_t *p = guest_memory_pointer(address, size, 0);
    if (!p) return 0;
    for (uint32_t i = 0; i < size; ++i)
        if (p[i] != expected) return 0;
    return 1;
}

int main(void) {
    CHECK(!guest_memory_init());
    GuestHeapSet set = {0};
    uint32_t heap = UINT32_C(0xaaaaaaaa);
    uint64_t committed_before = guest_memory_committed();

    CHECK(!guest_heap_create(&set, 0, 128, &heap));
    CHECK(heap == GUEST_HEAP_BASE);
    CHECK(guest_memory_committed() == committed_before + GUEST_MEMORY_GRANULE);
    CHECK(guest_memory_pointer(heap, GUEST_MEMORY_GRANULE, 1) != NULL);
    CHECK(guest_memory_pointer(heap + GUEST_MEMORY_GRANULE, 1, 0) == NULL);

    /* Zero-size blocks are real, unique, aligned allocations with reported size 0. */
    uint32_t z0 = 0, z1 = 0, z2 = 0, size = UINT32_C(0xdeadbeef);
    CHECK(!guest_heap_alloc(&set, heap, 0, 0, &z0));
    CHECK(!guest_heap_alloc(&set, heap, 0, 1, &z1));
    CHECK(!guest_heap_alloc(&set, heap, 0, 0, &z2));
    CHECK(z0 != z1 && z0 != z2 && z1 != z2);
    CHECK(!(z0 & 7u) && !(z1 & 7u) && !(z2 & 7u));
    CHECK(!guest_heap_size(&set, heap, z0, &size) && size == 0);
    CHECK(!guest_heap_size(&set, heap, z1, &size) && size == 0);
    CHECK(!guest_heap_size(&set, heap, z2, &size) && size == 0);
    CHECK(guest_memory_pointer(z0, 1, 1) != NULL);
    CHECK(guest_memory_committed() == committed_before + 2u * GUEST_MEMORY_GRANULE);

    /* Null free is harmless; a real free is reusable and double-free is rejected. */
    CHECK(!guest_heap_free(&set, heap, 0));
    CHECK(!guest_heap_free(&set, heap, z1));
    CHECK(guest_heap_free(&set, heap, z1) == EINVAL);
    size = UINT32_C(0xdeadbeef);
    CHECK(guest_heap_size(&set, heap, z1, &size) == EINVAL);
    CHECK(size == UINT32_C(0xdeadbeef));
    uint32_t reused = 0;
    CHECK(!guest_heap_alloc(&set, heap, 0, 1, &reused));
    CHECK(reused == z1 && guest_memory_pointer(reused, 1, 1) != NULL);

    /* Adjacent freed spans coalesce in the free search, without overlaps. */
    CHECK(!guest_heap_destroy(&set, heap));
    CHECK(guest_memory_pointer(heap, 1, 0) == NULL);
    CHECK(guest_memory_pointer(z0, 1, 0) == NULL);

    GuestHeapSet gaps = {0};
    uint32_t gap_heap = 0;
    CHECK(!guest_heap_create(&gaps, 0, 128, &gap_heap));
    uint32_t a = 0, b = 0, c = 0, d = 0;
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 1, &a));
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 1, &b));
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 1, &c));
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 1, &d));
    CHECK(a + 8u == b && b + 8u == c && c + 8u == d);
    uint8_t *d_bytes = guest_memory_pointer(d, 8, 1);
    CHECK(d_bytes != NULL);
    memset(d_bytes, 0xd7, 8);
    uint8_t *a_bytes = guest_memory_pointer(a, 8, 1);
    CHECK(a_bytes != NULL);
    memset(a_bytes, 0xa6, 8);
    CHECK(!guest_heap_free(&gaps, gap_heap, a));
    uint32_t zeroed_reuse = 0;
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 1, &zeroed_reuse));
    CHECK(zeroed_reuse == a && all_bytes_are(zeroed_reuse, 8, 0));
    CHECK(!guest_heap_free(&gaps, gap_heap, b));
    CHECK(!guest_heap_free(&gaps, gap_heap, c));
    CHECK(guest_heap_free(&gaps, gap_heap, b) == EINVAL);
    size = UINT32_C(0xdeadbeef);
    CHECK(guest_heap_size(&gaps, gap_heap, c, &size) == EINVAL);
    CHECK(size == UINT32_C(0xdeadbeef));
    uint32_t merged = 0;
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 16, 1, &merged));
    CHECK(merged == b);
    CHECK(!guest_heap_size(&gaps, gap_heap, merged, &size) && size == 16);
    CHECK(guest_memory_pointer(merged, 16, 1) != NULL);
    CHECK(all_bytes_are(d, 8, 0xd7));
    uint32_t after = 0;
    CHECK(!guest_heap_alloc(&gaps, gap_heap, 8, 0, &after));
    CHECK(after == d + 8u && after >= merged + 16u);
    CHECK(!guest_heap_destroy(&gaps, gap_heap));

    /* Fixed capacity includes rounded allocation spans and failures are atomic. */
    GuestHeapSet fixed = {0};
    uint32_t fixed_heap = 0;
    CHECK(!guest_heap_create(&fixed, 32, 64, &fixed_heap));
    uint32_t full = UINT32_C(0x12345678);
    CHECK(!guest_heap_alloc(&fixed, fixed_heap, 64, 0, &full));
    CHECK(full == fixed_heap + GUEST_MEMORY_GRANULE);
    GuestHeap fixed_before = fixed.heaps[0];
    uint64_t fixed_committed = guest_memory_committed();
    uint32_t failed_address = UINT32_C(0x87654321);
    CHECK(guest_heap_alloc(&fixed, fixed_heap, 1, 0, &failed_address) == ENOMEM);
    CHECK(failed_address == UINT32_C(0x87654321));
    CHECK(!memcmp(&fixed_before, &fixed.heaps[0], sizeof fixed_before));
    CHECK(guest_memory_committed() == fixed_committed);
    CHECK(guest_heap_alloc(&fixed, fixed_heap, UINT32_MAX, 0, &failed_address) == ENOMEM);
    CHECK(failed_address == UINT32_C(0x87654321));
    CHECK(!guest_heap_destroy(&fixed, fixed_heap));

    GuestHeapSet fixed_boundary = {0};
    uint32_t boundary_heap = 0;
    CHECK(!guest_heap_create(&fixed_boundary, 0, 0x80000u, &boundary_heap));
    failed_address = UINT32_C(0x87654321);
    CHECK(guest_heap_alloc(&fixed_boundary, boundary_heap, 0x7fff8u, 0,
                           &failed_address) == ENOMEM);
    CHECK(failed_address == UINT32_C(0x87654321));
    uint32_t below_cutoff = 0;
    CHECK(!guest_heap_alloc(&fixed_boundary, boundary_heap, 0x7fff7u, 0,
                            &below_cutoff));
    CHECK(!guest_heap_size(&fixed_boundary, boundary_heap, below_cutoff, &size));
    CHECK(size == 0x7fff7u);
    CHECK(!guest_heap_destroy(&fixed_boundary, boundary_heap));

    /* The fixed host metadata cap is explicit; a freed slot can be reused. */
    GuestHeapSet blocks = {0};
    uint32_t blocks_heap = 0;
    CHECK(!guest_heap_create(&blocks, 0, 4096, &blocks_heap));
    uint32_t block_addresses[GUEST_HEAP_MAX_BLOCKS];
    for (unsigned i = 0; i < GUEST_HEAP_MAX_BLOCKS; ++i) {
        CHECK(!guest_heap_alloc(&blocks, blocks_heap, 0, 0, &block_addresses[i]));
        CHECK(!(block_addresses[i] & 7u));
        for (unsigned j = 0; j < i; ++j)
            CHECK(block_addresses[i] != block_addresses[j]);
    }
    GuestHeap blocks_before = blocks.heaps[0];
    uint64_t blocks_committed = guest_memory_committed();
    failed_address = UINT32_C(0x87654321);
    CHECK(guest_heap_alloc(&blocks, blocks_heap, 0, 0, &failed_address) == ENOMEM);
    CHECK(failed_address == UINT32_C(0x87654321));
    CHECK(!memcmp(&blocks_before, &blocks.heaps[0], sizeof blocks_before));
    CHECK(guest_memory_committed() == blocks_committed);
    CHECK(!guest_heap_free(&blocks, blocks_heap, block_addresses[127]));
    uint32_t recycled_slot = 0;
    CHECK(!guest_heap_alloc(&blocks, blocks_heap, 0, 1, &recycled_slot));
    CHECK(recycled_slot == block_addresses[127]);
    CHECK(guest_memory_pointer(recycled_slot, 1, 1) != NULL);
    CHECK(!guest_heap_destroy(&blocks, blocks_heap));

    /* Destroy revokes all heap access; recreation reuses the handle without stale blocks. */
    GuestHeapSet life = {0};
    uint32_t life_heap = 0;
    CHECK(!guest_heap_create(&life, 0, 128, &life_heap));
    uint32_t old_block = 0;
    CHECK(!guest_heap_alloc(&life, life_heap, 8, 0, &old_block));
    uint8_t *old_bytes = guest_memory_pointer(old_block, 8, 1);
    CHECK(old_bytes != NULL);
    memset(old_bytes, 0xa5, 8);
    uint64_t before_destroy = guest_memory_committed();
    CHECK(!guest_heap_destroy(&life, life_heap));
    CHECK(guest_memory_committed() == before_destroy);
    CHECK(guest_memory_pointer(life_heap, 1, 0) == NULL);
    CHECK(guest_memory_pointer(old_block, 1, 0) == NULL);
    size = UINT32_C(0xdeadbeef);
    CHECK(guest_heap_size(&life, life_heap, old_block, &size) == EINVAL);
    CHECK(size == UINT32_C(0xdeadbeef));
    CHECK(guest_heap_free(&life, life_heap, old_block) == EINVAL);
    CHECK(guest_heap_destroy(&life, life_heap) == EINVAL);
    uint32_t recreated = 0;
    CHECK(!guest_heap_create(&life, 0, 128, &recreated));
    CHECK(recreated == life_heap);
    CHECK(guest_memory_pointer(old_block, 1, 0) == NULL);
    uint32_t fresh = 0;
    CHECK(!guest_heap_alloc(&life, recreated, 8, 1, &fresh));
    CHECK(fresh == old_block && all_bytes_are(fresh, 8, 0));
    CHECK(!guest_heap_destroy(&life, recreated));

    /* Heap slots map to disjoint fixed arenas; the fifth heap fails unchanged. */
    GuestHeapSet slots = {0};
    uint32_t handles[GUEST_HEAP_MAX_HEAPS];
    for (unsigned i = 0; i < GUEST_HEAP_MAX_HEAPS; ++i) {
        handles[i] = 0;
        CHECK(!guest_heap_create(&slots, 0, 0, &handles[i]));
        CHECK(handles[i] == GUEST_HEAP_BASE + i * GUEST_HEAP_ARENA_SIZE);
    }
    GuestHeapSet slots_before = slots;
    uint32_t no_handle = UINT32_C(0xcafebabe);
    CHECK(guest_heap_create(&slots, 0, 0, &no_handle) == ENOMEM);
    CHECK(no_handle == UINT32_C(0xcafebabe));
    CHECK(!memcmp(&slots_before, &slots, sizeof slots_before));
    CHECK(!guest_heap_destroy(&slots, handles[1]));
    no_handle = 0;
    CHECK(!guest_heap_create(&slots, 0, 0, &no_handle));
    CHECK(no_handle == handles[1]);
    for (unsigned i = 0; i < GUEST_HEAP_MAX_HEAPS; ++i)
        CHECK(!guest_heap_destroy(&slots, slots.heaps[i].handle));

    /* Invalid requests do not change metadata or caller outputs. */
    GuestHeapSet invalid = {0};
    uint32_t sentinel = UINT32_C(0x13579bdf);
    CHECK(guest_heap_create(NULL, 0, 0, &sentinel) == EINVAL);
    CHECK(sentinel == UINT32_C(0x13579bdf));
    CHECK(guest_heap_create(&invalid, 65, 64, &sentinel) == EINVAL);
    CHECK(sentinel == UINT32_C(0x13579bdf));
    CHECK(guest_heap_create(&invalid, 0, GUEST_HEAP_ARENA_SIZE, &sentinel) == ENOMEM);
    CHECK(sentinel == UINT32_C(0x13579bdf));
    CHECK(!memcmp(&invalid, &(GuestHeapSet){0}, sizeof invalid));
    CHECK(guest_heap_alloc(&invalid, 1, 8, 0, &sentinel) == EINVAL);
    CHECK(sentinel == UINT32_C(0x13579bdf));
    CHECK(guest_heap_free(&invalid, 1, 0) == EINVAL);
    size = UINT32_C(0xdeadbeef);
    CHECK(guest_heap_size(&invalid, 1, 1, &size) == EINVAL);
    CHECK(size == UINT32_C(0xdeadbeef));

    /* Reallocation in-place, relocation, HEAP_ZERO_MEMORY, in-place-only flag, and error preservation */
    GuestHeapSet rset = {0};
    uint32_t rheap = 0;
    CHECK(!guest_heap_create(&rset, 0, 1024, &rheap));
    uint32_t blk1 = 0, blk2 = 0;
    CHECK(!guest_heap_alloc(&rset, rheap, 16, 1, &blk1));
    CHECK(!guest_heap_alloc(&rset, rheap, 16, 1, &blk2));
    uint8_t *b1_data = guest_memory_pointer(blk1, 16, 1);
    memset(b1_data, 0x42, 16);

    uint32_t r_addr = UINT32_C(0xdeadbeef);
    CHECK(guest_heap_realloc(&rset, rheap, 0x10, blk1, 32, &r_addr) == ENOMEM);
    CHECK(r_addr == UINT32_C(0xdeadbeef));

    CHECK(!guest_heap_realloc(&rset, rheap, 0x8, blk1, 32, &r_addr));
    CHECK(r_addr != blk1);
    CHECK(r_addr >= blk2 + 16u);
    CHECK(all_bytes_are(r_addr, 16, 0x42));
    CHECK(all_bytes_are(r_addr + 16, 16, 0));
    CHECK(!guest_heap_size(&rset, rheap, r_addr, &size) && size == 32);

    uint32_t in_place_addr = 0;
    CHECK(!guest_heap_realloc(&rset, rheap, 0x8, r_addr, 48, &in_place_addr));
    CHECK(in_place_addr == r_addr);
    CHECK(all_bytes_are(in_place_addr, 16, 0x42));
    CHECK(all_bytes_are(in_place_addr + 16, 32, 0));
    CHECK(!guest_heap_size(&rset, rheap, in_place_addr, &size) && size == 48);

    uint32_t shrink_addr = 0;
    CHECK(!guest_heap_realloc(&rset, rheap, 0, in_place_addr, 8, &shrink_addr));
    CHECK(shrink_addr == in_place_addr);
    CHECK(all_bytes_are(shrink_addr, 8, 0x42));
    CHECK(!guest_heap_size(&rset, rheap, shrink_addr, &size) && size == 8);

    CHECK(guest_heap_realloc(&rset, rheap, 0, 0, 16, &sentinel) == EINVAL);
    CHECK(guest_heap_realloc(&rset, rheap, 0, 0x12345678, 16, &sentinel) == EINVAL);
    CHECK(guest_heap_realloc(&rset, 0, 0, shrink_addr, 16, &sentinel) == EINVAL);
    CHECK(guest_heap_realloc(NULL, rheap, 0, shrink_addr, 16, &sentinel) == EINVAL);
    CHECK(guest_heap_realloc(&rset, rheap, 0, shrink_addr, 16, NULL) == EINVAL);

    CHECK(!guest_heap_destroy(&rset, rheap));

    CHECK(!guest_memory_shutdown());
    puts("PASS | guest heap | bounded arenas, zero blocks, reuse/coalescing, realloc in-place/relocate, atomic failures, metadata cap, lifecycle");
    return 0;
}
