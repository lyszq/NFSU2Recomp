#ifndef NFSU2_GUEST_TLS_H
#define NFSU2_GUEST_TLS_H
#include <stdint.h>
/* Bounded x86 Windows dynamic TLS policy: 64 process keys, 64 guest threads.
 * TlsSlots is separate from the static PE TLS vector at TEB+0x2c. No host TLS
 * keys or native thread identities are used. Caller serializes all operations,
 * thread lifecycle and guest mapping changes. Zero-initialize before use.
 * Invalid/unallocated-key use is a strict runtime state error, not a claimed
 * Windows invalid-use contract. Expansion slots are not implemented. */
#define GUEST_TLS_SLOTS 64u
#define GUEST_TLS_THREADS 64u
#define GUEST_TLS_OFFSET 0xe10u
typedef struct GuestTLSSet {
    uint64_t allocated;
    uint32_t count;
    struct { uint32_t teb, id; } threads[GUEST_TLS_THREADS];
} GuestTLSSet;
typedef enum GuestTLSOperation { GUEST_TLS_ALLOC, GUEST_TLS_FREE,
    GUEST_TLS_GET, GUEST_TLS_SET } GuestTLSOperation;
/* Auto-registers the current TEB transactionally. New thread values are zero.
 * Allocation/free clear that key for all registered threads after preflighting
 * every affected range. On failure CPU, metadata, values and result stay intact;
 * fault receives the failing guest address. ENOSPC is bounded resource exhaustion.
 * Values are raw guest DWORDs; pointed-to storage is never accessed/freed. */
int guest_tls_apply(GuestTLSSet *, uint32_t teb, GuestTLSOperation,
                    uint32_t index, uint32_t value, uint32_t *result, uint32_t *fault);
/* Quiesced detach/cleanup touch metadata only, even after VM shutdown. */
int guest_tls_detach(GuestTLSSet *, uint32_t teb);
void guest_tls_cleanup(GuestTLSSet *);
unsigned guest_tls_count(const GuestTLSSet *);
#endif
