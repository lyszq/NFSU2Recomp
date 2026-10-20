#include "guest_tls.h"
#include "guest_memory.h"
#include <errno.h>
#include <string.h>
static uint32_t get32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static void put32(void *p,uint32_t v) { memcpy(p,&v,4); }
static void *at(uint32_t teb, uint32_t offset, size_t size, int write, uint32_t *fault) {
    uint64_t address=(uint64_t)teb+offset;
    void *p=address<=UINT32_MAX ? guest_memory_pointer((uint32_t)address,size,write) : NULL;
    if (!p) *fault=address<=UINT32_MAX ? (uint32_t)address : UINT32_MAX;
    return p;
}
int guest_tls_apply(GuestTLSSet *s,uint32_t teb,GuestTLSOperation op,
                    uint32_t index,uint32_t value,uint32_t *result,uint32_t *fault) {
    if (!s || !result || !fault) return EINVAL;
    *fault=teb;
    if (!teb || s->count>GUEST_TLS_THREADS || op>GUEST_TLS_SET || (int)op<0) return EINVAL;
    if (op!=GUEST_TLS_ALLOC && (index>=GUEST_TLS_SLOTS || !(s->allocated & (UINT64_C(1)<<index))))
        return EINVAL;
    const void *identity=at(teb,0x24u,4,0,fault);
    if (!identity) return EFAULT;
    uint32_t id=get32(identity);
    if (!id || (uint64_t)teb+GUEST_TLS_OFFSET+4*GUEST_TLS_SLOTS>UINT64_C(0x100000000)) return EINVAL;
    unsigned current=s->count;
    for (unsigned i=0;i<s->count;i++) {
        if (s->threads[i].teb==teb) {
            if (s->threads[i].id!=id) return EINVAL;
            current=i;
        } else if (s->threads[i].id==id ||
                   ((uint64_t)teb<s->threads[i].teb+UINT64_C(0x1000) &&
                    (uint64_t)s->threads[i].teb<(uint64_t)teb+0x1000u)) return EINVAL;
    }
    int fresh=current==s->count;
    if (fresh && s->count==GUEST_TLS_THREADS) return ENOSPC;
    if (op==GUEST_TLS_ALLOC) {
        for (index=0;index<GUEST_TLS_SLOTS;index++)
            if (!(s->allocated & (UINT64_C(1)<<index))) break;
        if (index==GUEST_TLS_SLOTS) return ENOSPC;
    }
    void *new_slots=fresh ? at(teb,GUEST_TLS_OFFSET,4*GUEST_TLS_SLOTS,1,fault) : NULL;
    if (fresh && !new_slots) return EFAULT;
    void *slot=at(teb,GUEST_TLS_OFFSET+index*4u,4,op!=GUEST_TLS_GET,fault);
    if (!slot) return EFAULT;
    /* Preflight every write/identity before clearing anything or registering a
     * thread. Mapping lifetime is held by the caller for this whole operation. */
    void *others[GUEST_TLS_THREADS];
    if (op==GUEST_TLS_ALLOC || op==GUEST_TLS_FREE) {
        for (unsigned i=0;i<s->count;i++) {
            identity=at(s->threads[i].teb,0x24u,4,0,fault);
            if (!identity) return EFAULT;
            if (get32(identity)!=s->threads[i].id) { *fault=s->threads[i].teb; return EINVAL; }
            others[i]=at(s->threads[i].teb,GUEST_TLS_OFFSET+index*4u,4,1,fault);
            if (!others[i]) return EFAULT;
        }
    }
    if (fresh) {
        memset(new_slots,0,4*GUEST_TLS_SLOTS);
        s->threads[s->count].teb=teb; s->threads[s->count].id=id; s->count++;
    }
    uint32_t output=1;
    if (op==GUEST_TLS_ALLOC || op==GUEST_TLS_FREE) {
        /* count may include the newly registered thread; its slot is already
         * zero, while others[] contains exactly the preexisting threads. */
        unsigned previous=s->count-(unsigned)fresh;
        for (unsigned i=0;i<previous;i++) put32(others[i],0);
        put32(slot,0);
        if (op==GUEST_TLS_ALLOC) { s->allocated|=UINT64_C(1)<<index; output=index; }
        else s->allocated&=~(UINT64_C(1)<<index);
    } else if (op==GUEST_TLS_SET) put32(slot,value);
    else output=get32(slot);
    *result=output;
    return 0;
}
int guest_tls_detach(GuestTLSSet *s,uint32_t teb) {
    if (!s || s->count>GUEST_TLS_THREADS) return EINVAL;
    for (unsigned i=0;i<s->count;i++) if (s->threads[i].teb==teb) {
        s->threads[i]=s->threads[--s->count];
        memset(&s->threads[s->count],0,sizeof s->threads[0]); return 0;
    }
    return ENOENT;
}
void guest_tls_cleanup(GuestTLSSet *s) { if (s) memset(s,0,sizeof *s); }
unsigned guest_tls_count(const GuestTLSSet *s) {
    unsigned n=0; uint64_t keys=s ? s->allocated : 0;
    while (keys) { keys&=keys-1; n++; } return n;
}
