#include "guest_critical.h"
#include "guest_memory.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL guest critical line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

#define BASE 0x10000u

static int snapshot(uint32_t address, uint8_t bytes[GUEST_CRITICAL_BYTES]) {
    const void *p = guest_memory_pointer(address, GUEST_CRITICAL_BYTES, 0);
    if (!p) return 0;
    memcpy(bytes, p, GUEST_CRITICAL_BYTES);
    return 1;
}

static int mirror_is(uint32_t address, uint32_t recursion, uint32_t thread_id) {
    uint32_t expected[6] = {
        0,
        recursion ? recursion - 1u : UINT32_MAX,
        recursion,
        thread_id,
        0,
        0
    };
    const void *p = guest_memory_pointer(address, GUEST_CRITICAL_BYTES, 0);
    return p && !memcmp(p, expected, sizeof expected);
}

typedef struct ThreadAttempt {
    GuestCriticalSet *set;
    uint32_t address, thread_id;
    int release_after_acquire;
    int acquire_result, release_result;
} ThreadAttempt;

static void *attempt_section(void *opaque) {
    ThreadAttempt *attempt = opaque;
    attempt->acquire_result = guest_critical_acquire(
        attempt->set, attempt->address, attempt->thread_id);
    attempt->release_result = -1;
    if (attempt->release_after_acquire && !attempt->acquire_result)
        attempt->release_result = guest_critical_release(
            attempt->set, attempt->address, attempt->thread_id);
    else if (!attempt->release_after_acquire)
        attempt->release_result = guest_critical_release(
            attempt->set, attempt->address, attempt->thread_id);
    return NULL;
}

typedef struct HoldThread {
    GuestCriticalSet *set;
    uint32_t address, thread_id;
    pthread_mutex_t gate_mutex;
    pthread_cond_t gate_condition;
    int ready, finish, acquire_result, release_result;
} HoldThread;

static void *hold_section(void *opaque) {
    HoldThread *hold = opaque;
    hold->acquire_result = guest_critical_acquire(
        hold->set, hold->address, hold->thread_id);
    pthread_mutex_lock(&hold->gate_mutex);
    hold->ready = 1;
    pthread_cond_broadcast(&hold->gate_condition);
    while (!hold->finish)
        pthread_cond_wait(&hold->gate_condition, &hold->gate_mutex);
    pthread_mutex_unlock(&hold->gate_mutex);
    hold->release_result = hold->acquire_result ? -1 : guest_critical_release(
        hold->set, hold->address, hold->thread_id);
    return NULL;
}

int main(void) {
    CHECK(!guest_memory_init());
    CHECK(!guest_memory_commit(BASE, 4u * GUEST_MEMORY_GRANULE));
    CHECK(guest_critical_count(NULL) == 0);
    CHECK(guest_critical_cleanup(NULL) == EINVAL);

    GuestCriticalSet invalid = {0};
    CHECK(guest_critical_create(NULL, BASE) == EINVAL);
    CHECK(guest_critical_create(&invalid, 0) == EFAULT);
    CHECK(guest_critical_create(&invalid, UINT32_MAX - 7u) == EFAULT);
    CHECK(!invalid.state && guest_critical_count(&invalid) == 0);

    /* A whole 24-byte object must be writable, even when it crosses a page. */
    uint32_t guarded_page = BASE + 3u * GUEST_MEMORY_GRANULE;
    CHECK(!guest_memory_protect(guarded_page, GUEST_MEMORY_GRANULE,
                                GUEST_MEMORY_NONE));
    uint32_t inaccessible = guarded_page - 7u;
    CHECK(guest_critical_create(&invalid, inaccessible) == EFAULT);
    CHECK(!invalid.state && guest_critical_count(&invalid) == 0);
    CHECK(!guest_memory_protect(guarded_page, GUEST_MEMORY_GRANULE,
                                GUEST_MEMORY_READ_WRITE));

    /* Unaligned and cross-granule objects work with checked host access. */
    GuestCriticalSet cross_page = {0};
    uint32_t crossing = BASE + GUEST_MEMORY_GRANULE - 7u;
    CHECK(!guest_critical_create(&cross_page, crossing));
    CHECK(guest_critical_count(&cross_page) == 1);
    CHECK(mirror_is(crossing, 0, 0));
    CHECK(!guest_critical_delete(&cross_page, crossing));
    CHECK(guest_critical_count(&cross_page) == 0);
    CHECK(!guest_critical_cleanup(&cross_page));

    GuestCriticalSet set = {0};
    uint32_t address = BASE + 1u;
    CHECK(!guest_critical_create(&set, address));
    CHECK(guest_critical_count(&set) == 1 && mirror_is(address, 0, 0));

    uint8_t before[GUEST_CRITICAL_BYTES], after[GUEST_CRITICAL_BYTES];
    CHECK(snapshot(address, before));
    CHECK(guest_critical_create(&set, address) == EINVAL); /* duplicate */
    CHECK(snapshot(address, after) && !memcmp(before, after, sizeof before));
    uint32_t overlapping = address + 16u;
    CHECK(snapshot(overlapping, before));
    CHECK(guest_critical_create(&set, overlapping) == EINVAL);
    CHECK(snapshot(overlapping, after) && !memcmp(before, after, sizeof before));

    /* Exactly adjacent 24-byte objects do not overlap. */
    uint32_t adjacent = address + GUEST_CRITICAL_BYTES;
    CHECK(!guest_critical_create(&set, adjacent));
    CHECK(guest_critical_count(&set) == 2 && mirror_is(adjacent, 0, 0));

    /* Guest corruption of the opaque mirror is rejected without lock mutation. */
    CHECK(snapshot(address, before));
    uint8_t *corruptible = guest_memory_pointer(address, GUEST_CRITICAL_BYTES, 1);
    CHECK(corruptible != NULL);
    corruptible[0] = 1;
    CHECK(snapshot(address, after));
    CHECK(guest_critical_acquire(&set, address, 11) == EINVAL);
    CHECK(guest_critical_release(&set, address, 11) == EINVAL);
    CHECK(guest_critical_delete(&set, address) == EINVAL);
    uint8_t still_corrupt[GUEST_CRITICAL_BYTES];
    CHECK(snapshot(address, still_corrupt));
    CHECK(!memcmp(after, still_corrupt, sizeof after));
    memcpy(corruptible, before, sizeof before);
    CHECK(mirror_is(address, 0, 0));

    /* Read-only, uncommitted, or overflowing guest objects fail without state changes. */
    CHECK(snapshot(address, before));
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_READ));
    CHECK(guest_critical_acquire(&set, address, 11) == EFAULT);
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_READ_WRITE));
    CHECK(snapshot(address, after) && !memcmp(before, after, sizeof before));
    CHECK(guest_critical_acquire(&set, BASE + 2u * GUEST_MEMORY_GRANULE, 11) == EINVAL);
    CHECK(guest_critical_release(&set, BASE + 2u * GUEST_MEMORY_GRANULE, 11) == EINVAL);

    /* Recursive acquire/release mirrors all six guest words exactly. */
    CHECK(guest_critical_acquire(&set, address, 11) == 0);
    CHECK(mirror_is(address, 1, 11));
    CHECK(guest_critical_acquire(&set, address, 11) == 0);
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_acquire(&set, address, 0) == EINVAL);
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_acquire(&set, address, 12) == EBUSY);
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_release(&set, address, 12) == EPERM);
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_release(&set, address, 0) == EINVAL);
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_delete(&set, address) == EBUSY);
    CHECK(mirror_is(address, 2, 11));

    /* Another native thread cannot acquire or release the owner's section. */
    CHECK(snapshot(address, before));
    ThreadAttempt blocked = {
        .set = &set, .address = address, .thread_id = 22,
        .release_after_acquire = 0, .acquire_result = -1, .release_result = -1
    };
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, attempt_section, &blocked));
    CHECK(!pthread_join(thread, NULL));
    CHECK(blocked.acquire_result == EBUSY && blocked.release_result == EPERM);
    CHECK(snapshot(address, after) && !memcmp(before, after, sizeof before));
    CHECK(mirror_is(address, 2, 11));

    /* A release fault must leave the real native lock held. */
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_NONE));
    CHECK(guest_critical_release(&set, address, 11) == EFAULT);
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_READ_WRITE));
    CHECK(mirror_is(address, 2, 11));
    CHECK(guest_critical_release(&set, address, 11) == 0);
    CHECK(mirror_is(address, 1, 11));
    CHECK(guest_critical_release(&set, address, 11) == 0);
    CHECK(mirror_is(address, 0, 0));

    /* A foreign native owner succeeds after the original owner releases. */
    ThreadAttempt succeeds = {
        .set = &set, .address = address, .thread_id = 22,
        .release_after_acquire = 1, .acquire_result = -1, .release_result = -1
    };
    CHECK(!pthread_create(&thread, NULL, attempt_section, &succeeds));
    CHECK(!pthread_join(thread, NULL));
    CHECK(!succeeds.acquire_result && !succeeds.release_result);
    CHECK(mirror_is(address, 0, 0));

    CHECK(!guest_critical_delete(&set, address));
    CHECK(guest_critical_count(&set) == 1);
    uint32_t zeros[6] = {0};
    const void *deleted = guest_memory_pointer(address, GUEST_CRITICAL_BYTES, 0);
    CHECK(deleted && !memcmp(deleted, zeros, sizeof zeros));
    CHECK(guest_critical_delete(&set, address) == EINVAL);

    /* A tracked object whose guest bytes become inaccessible cannot be deleted. */
    CHECK(snapshot(adjacent, before));
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_NONE));
    CHECK(guest_critical_delete(&set, adjacent) == EFAULT);
    CHECK(guest_critical_count(&set) == 1);
    CHECK(!guest_memory_protect(BASE, GUEST_MEMORY_GRANULE, GUEST_MEMORY_READ_WRITE));
    CHECK(snapshot(adjacent, after) && !memcmp(before, after, sizeof before));
    CHECK(!guest_critical_delete(&set, adjacent));
    CHECK(guest_critical_count(&set) == 0);
    CHECK(guest_critical_delete(&set, adjacent) == EINVAL);
    CHECK(!guest_critical_cleanup(&set));
    CHECK(!set.state && guest_critical_count(&set) == 0);

    /* The fixed metadata cap rejects the next valid object without writing it. */
    GuestCriticalSet capped = {0};
    uint32_t addresses[GUEST_CRITICAL_MAX];
    for (unsigned i = 0; i < GUEST_CRITICAL_MAX; ++i) {
        addresses[i] = BASE + 0x1000u + i * GUEST_CRITICAL_BYTES;
        CHECK(!guest_critical_create(&capped, addresses[i]));
    }
    CHECK(guest_critical_count(&capped) == GUEST_CRITICAL_MAX);
    uint32_t over_cap = BASE + 0x1000u + GUEST_CRITICAL_MAX * GUEST_CRITICAL_BYTES;
    uint8_t *over_cap_bytes = guest_memory_pointer(over_cap, GUEST_CRITICAL_BYTES, 1);
    CHECK(over_cap_bytes != NULL);
    memset(over_cap_bytes, 0xa5, GUEST_CRITICAL_BYTES);
    CHECK(snapshot(over_cap, before));
    CHECK(guest_critical_create(&capped, over_cap) == ENOSPC);
    CHECK(snapshot(over_cap, after) && !memcmp(before, after, sizeof before));
    CHECK(guest_critical_count(&capped) == GUEST_CRITICAL_MAX);
    CHECK(!guest_critical_delete(&capped, addresses[31]));
    CHECK(guest_critical_count(&capped) == GUEST_CRITICAL_MAX - 1u);
    CHECK(!guest_critical_create(&capped, over_cap));
    CHECK(guest_critical_count(&capped) == GUEST_CRITICAL_MAX);
    CHECK(mirror_is(over_cap, 0, 0));
    for (unsigned i = 0; i < GUEST_CRITICAL_MAX; ++i)
        if (i != 31) CHECK(!guest_critical_delete(&capped, addresses[i]));
    CHECK(!guest_critical_delete(&capped, over_cap));
    CHECK(guest_critical_count(&capped) == 0);
    CHECK(!guest_critical_cleanup(&capped));

    /* Cleanup refuses a foreign-owned native lock and preserves its guest mirror. */
    GuestCriticalSet foreign = {0};
    uint32_t foreign_address = BASE + 0x3000u;
    CHECK(!guest_critical_create(&foreign, foreign_address));
    HoldThread hold = {
        .set = &foreign, .address = foreign_address, .thread_id = 99,
        .ready = 0, .finish = 0, .acquire_result = -1, .release_result = -1
    };
    CHECK(!pthread_mutex_init(&hold.gate_mutex, NULL));
    CHECK(!pthread_cond_init(&hold.gate_condition, NULL));
    CHECK(!pthread_create(&thread, NULL, hold_section, &hold));
    CHECK(!pthread_mutex_lock(&hold.gate_mutex));
    while (!hold.ready)
        CHECK(!pthread_cond_wait(&hold.gate_condition, &hold.gate_mutex));
    CHECK(!pthread_mutex_unlock(&hold.gate_mutex));
    CHECK(!hold.acquire_result && mirror_is(foreign_address, 1, 99));
    CHECK(snapshot(foreign_address, before));
    int cleanup_while_foreign_owned = guest_critical_cleanup(&foreign);
    CHECK(guest_critical_count(&foreign) == 1);
    CHECK(snapshot(foreign_address, after) && !memcmp(before, after, sizeof before));
    CHECK(!pthread_mutex_lock(&hold.gate_mutex));
    hold.finish = 1;
    CHECK(!pthread_cond_broadcast(&hold.gate_condition));
    CHECK(!pthread_mutex_unlock(&hold.gate_mutex));
    CHECK(!pthread_join(thread, NULL));
    CHECK(cleanup_while_foreign_owned == EBUSY);
    CHECK(!hold.release_result && mirror_is(foreign_address, 0, 0));
    CHECK(!pthread_cond_destroy(&hold.gate_condition));
    CHECK(!pthread_mutex_destroy(&hold.gate_mutex));
    CHECK(!guest_critical_cleanup(&foreign));
    CHECK(!foreign.state && guest_critical_count(&foreign) == 0);

    /* Cleanup cancels recursive caller-owned locks without touching guest RAM. */
    GuestCriticalSet owned = {0};
    uint32_t owned_address = BASE + 0x2000u;
    CHECK(!guest_critical_create(&owned, owned_address));
    CHECK(!guest_critical_acquire(&owned, owned_address, 77));
    CHECK(!guest_critical_acquire(&owned, owned_address, 77));
    CHECK(mirror_is(owned_address, 2, 77));
    CHECK(snapshot(owned_address, before));
    /* The outstanding native lock must be cancellable after the mapping is gone. */
    CHECK(!guest_memory_shutdown());
    CHECK(!guest_critical_cleanup(&owned));
    CHECK(!owned.state && guest_critical_count(&owned) == 0);
    CHECK(!guest_memory_init());
    CHECK(!guest_memory_commit(BASE, 4u * GUEST_MEMORY_GRANULE));
    CHECK(!guest_critical_create(&owned, owned_address));
    CHECK(mirror_is(owned_address, 0, 0));
    CHECK(!guest_critical_delete(&owned, owned_address));
    CHECK(!guest_critical_cleanup(&owned));
    CHECK(!guest_critical_cleanup(&owned));

    CHECK(!guest_memory_shutdown());
    puts("PASS | guest critical sections | recursive mirror, native contention, checked memory, cap and cleanup");
    return 0;
}
