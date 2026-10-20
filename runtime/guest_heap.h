#ifndef NFSU2_GUEST_HEAP_H
#define NFSU2_GUEST_HEAP_H
#include <stdint.h>
#define GUEST_HEAP_BASE 0x20000000u
#define GUEST_HEAP_ARENA_SIZE 0x04000000u
#define GUEST_HEAP_MAX_HEAPS 4
#define GUEST_HEAP_MAX_BLOCKS 256
typedef struct GuestHeapBlock { uint32_t address, size, span; } GuestHeapBlock;
typedef struct GuestHeap {
    uint32_t handle, capacity, fixed;
    GuestHeapBlock blocks[GUEST_HEAP_MAX_BLOCKS];
} GuestHeap;
typedef struct GuestHeapSet { GuestHeap heaps[GUEST_HEAP_MAX_HEAPS]; } GuestHeapSet;
/* Caller zero initializes metadata, exclusively owns 0x20000000..0x30000000
 * and quiesces execution for lifecycle changes. No executable mappings.
 * errno results, output arguments unchanged on failure. Zero-size allocations
 * have unique 8-byte aligned addresses and recorded size zero. Host metadata
 * caps are explicit; exhaustion is an allocation failure, never a fake handle.
 * Destroy revokes all committed pages; mapping owner ultimately shuts down VM. */
int guest_heap_create(GuestHeapSet *, uint32_t initial, uint32_t maximum, uint32_t *handle);
int guest_heap_alloc(GuestHeapSet *, uint32_t handle, uint32_t size, int zero, uint32_t *address);
int guest_heap_free(GuestHeapSet *, uint32_t handle, uint32_t address);
int guest_heap_size(GuestHeapSet *, uint32_t handle, uint32_t address, uint32_t *size);
int guest_heap_destroy(GuestHeapSet *, uint32_t handle);
#endif
