#include "guest_heap.h"
#include "guest_memory.h"
#include <errno.h>
#include <string.h>
#define HEADER GUEST_MEMORY_GRANULE
static GuestHeap *find(GuestHeapSet *set, uint32_t handle) {
    if (set && handle) for (unsigned i=0;i<GUEST_HEAP_MAX_HEAPS;i++)
        if (set->heaps[i].handle==handle) return &set->heaps[i];
    return NULL;
}
int guest_heap_create(GuestHeapSet *set, uint32_t initial, uint32_t maximum, uint32_t *handle) {
    if (!set || !handle || !g_mem || (maximum && initial>maximum)) return EINVAL;
    uint32_t limit=GUEST_HEAP_ARENA_SIZE-HEADER;
    if (maximum) {
        if (maximum>limit) return ENOMEM;
        limit=maximum;
    }
    if (initial>limit) return ENOMEM;
    for (unsigned i=0;i<GUEST_HEAP_MAX_HEAPS;i++) if (!set->heaps[i].handle) {
        uint32_t base=GUEST_HEAP_BASE+i*GUEST_HEAP_ARENA_SIZE;
        int rc=guest_memory_commit(base,(uint64_t)HEADER+initial);
        if (rc) return rc;
        /* Recreated heaps must not inherit pages from their former owner. */
        memset(g_mem+base,0,HEADER+initial);
        set->heaps[i]=(GuestHeap){.handle=base,.capacity=limit,.fixed=maximum!=0};
        *handle=base; return 0;
    }
    return ENOMEM;
}
int guest_heap_alloc(GuestHeapSet *set, uint32_t handle, uint32_t size, int zero, uint32_t *address) {
    GuestHeap *heap=find(set,handle);
    if (!heap || !address) return EINVAL;
    if (heap->fixed && size>=0x7fff8u) return ENOMEM;
    uint64_t span=((uint64_t)(size ? size : 1)+7u)&~UINT64_C(7);
    if (span>heap->capacity) return ENOMEM;
    unsigned slot=GUEST_HEAP_MAX_BLOCKS;
    for (unsigned i=0;i<GUEST_HEAP_MAX_BLOCKS;i++) if (!heap->blocks[i].address) { slot=i; break; }
    if (slot==GUEST_HEAP_MAX_BLOCKS) return ENOMEM;
    uint32_t candidate=handle+HEADER;
    /* First fit over live blocks: freed adjacent gaps coalesce implicitly. */
    for (;;) {
        uint32_t next=candidate;
        for (unsigned i=0;i<GUEST_HEAP_MAX_BLOCKS;i++) {
            const GuestHeapBlock *b=&heap->blocks[i];
            if (b->address && (uint64_t)candidate+span>b->address &&
                candidate<(uint64_t)b->address+b->span && b->address+b->span>next)
                next=b->address+b->span;
        }
        if (next==candidate) break;
        candidate=next;
    }
    if ((uint64_t)candidate+span>(uint64_t)handle+HEADER+heap->capacity) return ENOMEM;
    int rc=guest_memory_commit(candidate,span);
    if (rc) return rc;
    if (zero) memset(g_mem+candidate,0,size);
    heap->blocks[slot]=(GuestHeapBlock){candidate,size,(uint32_t)span};
    *address=candidate; return 0;
}
int guest_heap_free(GuestHeapSet *set, uint32_t handle, uint32_t address) {
    GuestHeap *heap=find(set,handle);
    if (!heap) return EINVAL;
    if (!address) return 0;
    for (unsigned i=0;i<GUEST_HEAP_MAX_BLOCKS;i++) if (heap->blocks[i].address==address) {
        heap->blocks[i]=(GuestHeapBlock){0}; return 0;
    }
    return EINVAL;
}
int guest_heap_size(GuestHeapSet *set, uint32_t handle, uint32_t address, uint32_t *size) {
    GuestHeap *heap=find(set,handle);
    if (!heap || !size || !address) return EINVAL;
    for (unsigned i=0;i<GUEST_HEAP_MAX_BLOCKS;i++) if (heap->blocks[i].address==address) {
        *size=heap->blocks[i].size; return 0;
    }
    return EINVAL;
}
int guest_heap_destroy(GuestHeapSet *set, uint32_t handle) {
    GuestHeap *heap=find(set,handle);
    if (!heap) return EINVAL;
    /* Protect only allocated pages; uncommitted gaps must stay uncommitted. */
    for (uint32_t offset=0;offset<GUEST_HEAP_ARENA_SIZE;offset+=GUEST_MEMORY_GRANULE) {
        uint32_t at=handle+offset;
        if (guest_memory_pointer(at,1,0)) {
            int rc=guest_memory_protect(at,GUEST_MEMORY_GRANULE,GUEST_MEMORY_NONE);
            if (rc) return rc;
        }
    }
    *heap=(GuestHeap){0}; return 0;
}
