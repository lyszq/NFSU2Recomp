#include "guest_dispatch.h"
#include <errno.h>
#include <stdlib.h>

int guest_dispatch_init(GuestDispatch *table, uint32_t base, uint32_t size,
                         const uint32_t *addresses, const GuestFunction *functions,
                         uint32_t count) {
    if (!table || !size || count > size || size > 64u * 1024u * 1024u ||
        (uint64_t)base + size > UINT64_C(0x100000000) ||
        (count && (!addresses || !functions))) return EINVAL;
    if (table->indices) return EBUSY;
    uint32_t *indices = calloc(size, sizeof *indices);
    if (!indices) return ENOMEM;
    int rc = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t off = addresses[i] - base;
        if (off >= size || !functions[i]) { rc = EINVAL; break; }
        if (indices[off]) { rc = EEXIST; break; }
        indices[off] = i + 1;
    }
    if (rc) { free(indices); return rc; }
    *table = (GuestDispatch){base, size, count, indices, addresses, functions};
    return 0;
}
GuestFunction guest_dispatch_lookup(const GuestDispatch *table, uint32_t address) {
    if (!table || !table->indices) return NULL;
    uint32_t off = address - table->text_base;
    if (off >= table->text_size) return NULL;
    uint32_t index = table->indices[off];
    return index && index <= table->count ? table->functions[index - 1] : NULL;
}
void guest_dispatch_destroy(GuestDispatch *table) {
    if (!table) return;
    free(table->indices);
    *table = (GuestDispatch){0};
}
