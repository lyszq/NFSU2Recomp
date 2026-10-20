#ifndef NFSU2_GUEST_DISPATCH_H
#define NFSU2_GUEST_DISPATCH_H
#include "cpu.h"
#include <stddef.h>

typedef void (*GuestFunction)(CPU *);
typedef struct GuestDispatch {
    uint32_t text_base, text_size, count;
    uint32_t *indices;
    const uint32_t *addresses;
    const GuestFunction *functions;
} GuestDispatch;

/* Extracted O(1) address-index policy from dispatch.c. Zero-initialize before
 * init. The caller owns immutable address/function arrays until destroy.
 * Duplicate, out-of-range and null entries are errors, never silent aliases.
 * Init/destroy require an idle owner; lookup does not modify table or CPU.
 */
int guest_dispatch_init(GuestDispatch *table, uint32_t text_base, uint32_t text_size,
                         const uint32_t *addresses, const GuestFunction *functions,
                         uint32_t count);
GuestFunction guest_dispatch_lookup(const GuestDispatch *table, uint32_t address);
void guest_dispatch_destroy(GuestDispatch *table);
#endif
