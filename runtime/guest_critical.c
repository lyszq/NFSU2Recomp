#include "guest_critical.h"
#include "guest_memory.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct Section {
    uint32_t address, recursion, thread_id;
    pthread_mutex_t mutex;
} Section;
typedef struct CriticalState { Section sections[GUEST_CRITICAL_MAX]; } CriticalState;
static Section *find(GuestCriticalSet *set, uint32_t address) {
    CriticalState *state=set ? set->state : NULL;
    if (state && address) for (unsigned i=0;i<GUEST_CRITICAL_MAX;i++)
        if (state->sections[i].address==address) return &state->sections[i];
    return NULL;
}
static void mirror(void *pointer, const Section *section) {
    uint32_t words[6]={0, section->recursion ? section->recursion-1 : UINT32_MAX,
        section->recursion,section->thread_id,0,0};
    memcpy(pointer,words,sizeof words);
}
static int matches(const void *pointer, const Section *section) {
    uint32_t expected[6];
    mirror(expected,section);
    return !memcmp(pointer,expected,sizeof expected);
}
static void *object(uint32_t address) {
    return address ? guest_memory_pointer(address,GUEST_CRITICAL_BYTES,1) : NULL;
}
int guest_critical_create(GuestCriticalSet *set, uint32_t address) {
    if (!set) return EINVAL;
    void *pointer=object(address);
    if (!pointer) return EFAULT;
    CriticalState *state=set->state;
    unsigned slot=GUEST_CRITICAL_MAX;
    if (state) {
        for (unsigned i=0;i<GUEST_CRITICAL_MAX;i++) {
            uint32_t existing=state->sections[i].address;
            if (existing && (uint64_t)address+GUEST_CRITICAL_BYTES>existing &&
                address<(uint64_t)existing+GUEST_CRITICAL_BYTES) return EINVAL;
            if (!existing && slot==GUEST_CRITICAL_MAX) slot=i;
        }
    } else slot=0;
    if (slot==GUEST_CRITICAL_MAX) return ENOSPC;
    int fresh=!state;
    if (fresh) { state=calloc(1,sizeof *state); if (!state) return ENOMEM; }
    pthread_mutexattr_t attributes;
    int rc=pthread_mutexattr_init(&attributes);
    if (rc) { if (fresh) free(state); return rc; }
    rc=pthread_mutexattr_settype(&attributes,PTHREAD_MUTEX_RECURSIVE);
    if (!rc) rc=pthread_mutex_init(&state->sections[slot].mutex,&attributes);
    (void)pthread_mutexattr_destroy(&attributes);
    if (rc) { if (fresh) free(state); return rc; }
    state->sections[slot].address=address;
    state->sections[slot].recursion=state->sections[slot].thread_id=0;
    mirror(pointer,&state->sections[slot]);
    set->state=state;
    return 0;
}
int guest_critical_acquire(GuestCriticalSet *set, uint32_t address, uint32_t thread_id) {
    Section *section=find(set,address);
    if (!section || !thread_id) return EINVAL;
    void *pointer=object(address);
    if (!pointer) return EFAULT;
    int rc=pthread_mutex_trylock(&section->mutex);
    if (rc) return rc;
    if (!matches(pointer,section)) { (void)pthread_mutex_unlock(&section->mutex); return EINVAL; }
    if ((section->recursion && section->thread_id!=thread_id) || section->recursion==INT32_MAX) {
        rc=section->recursion==INT32_MAX ? EOVERFLOW : EBUSY;
        (void)pthread_mutex_unlock(&section->mutex);
        return rc;
    }
    section->recursion++;
    section->thread_id=thread_id;
    mirror(pointer,section);
    return 0;
}
int guest_critical_release(GuestCriticalSet *set, uint32_t address, uint32_t thread_id) {
    Section *section=find(set,address);
    if (!section || !thread_id) return EINVAL;
    void *pointer=object(address);
    if (!pointer) return EFAULT;
    /* Taking a temporary recursive level avoids racing an owner's metadata
     * or invoking native unlock from a thread that does not own the mutex. */
    int rc=pthread_mutex_trylock(&section->mutex);
    if (rc) return rc==EBUSY ? EPERM : rc;
    if (!matches(pointer,section)) { (void)pthread_mutex_unlock(&section->mutex); return EINVAL; }
    if (!section->recursion || section->thread_id!=thread_id) {
        (void)pthread_mutex_unlock(&section->mutex); return EPERM;
    }
    section->recursion--;
    if (!section->recursion) section->thread_id=0;
    mirror(pointer,section);
    rc=pthread_mutex_unlock(&section->mutex); /* temporary level */
    if (!rc) rc=pthread_mutex_unlock(&section->mutex); /* guest level */
    return rc;
}
int guest_critical_delete(GuestCriticalSet *set, uint32_t address) {
    Section *section=find(set,address);
    if (!section) return EINVAL;
    void *pointer=object(address);
    if (!pointer) return EFAULT;
    if (section->recursion) return EBUSY;
    if (!matches(pointer,section)) return EINVAL;
    int rc=pthread_mutex_destroy(&section->mutex);
    if (rc) return rc;
    section->address=section->thread_id=section->recursion=0;
    memset(pointer,0,GUEST_CRITICAL_BYTES);
    return 0;
}
int guest_critical_cleanup(GuestCriticalSet *set) {
    if (!set) return EINVAL;
    CriticalState *state=set->state;
    if (!state) return 0;
    /* Preflight every lock before deleting any. Lifecycle callers guarantee
     * no concurrent acquisition once this ownership check starts. */
    for (unsigned i=0;i<GUEST_CRITICAL_MAX;i++) if (state->sections[i].address) {
        int rc=pthread_mutex_trylock(&state->sections[i].mutex);
        if (rc) return rc;
        rc=pthread_mutex_unlock(&state->sections[i].mutex);
        if (rc) return rc;
    }
    for (unsigned i=0;i<GUEST_CRITICAL_MAX;i++) {
        Section *section=&state->sections[i];
        if (!section->address) continue;
        while (section->recursion) {
            int rc=pthread_mutex_unlock(&section->mutex);
            if (rc) return rc;
            section->recursion--;
        }
        int rc=pthread_mutex_destroy(&section->mutex);
        if (rc) return rc;
        section->address=0;
    }
    free(state); set->state=NULL;
    return 0;
}
uint32_t guest_critical_count(const GuestCriticalSet *set) {
    const CriticalState *state=set ? set->state : NULL;
    uint32_t count=0;
    if (state) for (unsigned i=0;i<GUEST_CRITICAL_MAX;i++) count+=!!state->sections[i].address;
    return count;
}
