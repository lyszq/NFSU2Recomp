#ifndef NFSU2_GUEST_CRITICAL_H
#define NFSU2_GUEST_CRITICAL_H
#include <stdint.h>
#define GUEST_CRITICAL_MAX 64
#define GUEST_CRITICAL_BYTES 24u
typedef struct GuestCriticalSet { void *state; } GuestCriticalSet;
/* Real native recursive mutexes; native pointers never enter guest memory.
 * Zero initialize the set. Caller quiesces all users for create/delete/cleanup,
 * mapping changes and count queries. Acquire/release can contend on native
 * threads; guest thread IDs must identify their native execution owners.
 * Acquisition is nonblocking (EBUSY); the runner can stop a guest Enter rather
 * than block its worker beyond the execution budget. TryEnter uses BOOL false.
 * Returns errno, preserves guest memory on failure. Whole 24-byte objects must
 * remain RW. Guest fields are an opaque mirror, not synchronization primitives.
 * Cleanup cancels caller-owned recursive locks and frees native resources;
 * foreign ownership returns EBUSY. It never accesses the guest mapping. */
int guest_critical_create(GuestCriticalSet *, uint32_t address);
int guest_critical_acquire(GuestCriticalSet *, uint32_t address, uint32_t thread_id);
int guest_critical_release(GuestCriticalSet *, uint32_t address, uint32_t thread_id);
int guest_critical_delete(GuestCriticalSet *, uint32_t address);
int guest_critical_cleanup(GuestCriticalSet *);
uint32_t guest_critical_count(const GuestCriticalSet *);
#endif
