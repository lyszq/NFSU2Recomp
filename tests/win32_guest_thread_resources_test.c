#include "../runtime/win32_guest_thread_resources.h"

#include <pthread.h>
#include <stdio.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, message); \
        return 1; \
    } \
} while (0)

static int test_full_capacity(void) {
    Win32GuestThreadResourcePool pool = {0};
    Win32GuestThreadReservation slots[WIN32_GUEST_THREAD_SLOT_COUNT];
    win32_guest_thread_resources_init(&pool);

    for (uint32_t i = 0; i < WIN32_GUEST_THREAD_SLOT_COUNT; ++i) {
        CHECK(win32_guest_thread_resources_reserve(&pool, &slots[i]) == 0,
              "a reservation within both dedicated ranges succeeds");
        CHECK(slots[i].active && slots[i].slot == i,
              "slot identity and active state are published");
        CHECK(slots[i].teb == WIN32_GUEST_THREAD_TEB_BASE +
                                  i * WIN32_GUEST_THREAD_TEB_SIZE,
              "TEB slots are unique and monotonic");
        CHECK(slots[i].stack_low == WIN32_GUEST_THREAD_STACK_BASE +
                                        i * WIN32_GUEST_THREAD_STACK_SIZE,
              "guest stacks are unique and monotonic");
        CHECK(slots[i].stack_high == slots[i].stack_low +
                                         WIN32_GUEST_THREAD_STACK_SIZE,
              "each guest stack has exactly one MiB");
        CHECK(slots[i].stack_high <= WIN32_GUEST_THREAD_STACK_LIMIT,
              "no child stack enters the primary guest stack");
    }

    Win32GuestThreadReservation unchanged = {
        UINT32_C(0xaaaaaaaa), UINT32_C(0xbbbbbbbb),
        UINT32_C(0xcccccccc), UINT16_C(0xdddd), 0
    };
    Win32GuestThreadReservation before = unchanged;
    CHECK(win32_guest_thread_resources_reserve(&pool, &unchanged) == ENOSPC,
          "the first slot past capacity fails closed");
    CHECK(unchanged.teb == before.teb &&
              unchanged.stack_low == before.stack_low &&
              unchanged.stack_high == before.stack_high &&
              unchanged.slot == before.slot && unchanged.active == before.active,
          "capacity failure leaves caller output unchanged");
    CHECK(slots[WIN32_GUEST_THREAD_SLOT_COUNT - 1].stack_high ==
              WIN32_GUEST_THREAD_STACK_LIMIT,
          "the last accepted stack ends exactly at the primary stack boundary");
    CHECK(slots[WIN32_GUEST_THREAD_SLOT_COUNT - 1].teb +
              WIN32_GUEST_THREAD_TEB_SIZE == WIN32_GUEST_THREAD_TEB_LIMIT,
          "the last accepted TEB ends at its exclusive range boundary");
    return 0;
}

static int test_suspended_and_failed_start(void) {
    Win32GuestThreadResourcePool pool = {0};
    Win32GuestThreadReservation timer, suspended, next, failed, replacement, after;
    win32_guest_thread_resources_init(&pool);

    CHECK(win32_guest_thread_resources_reserve(&pool, &timer) == 0,
          "the timer worker uses the same production resource pool");
    CHECK(win32_guest_thread_resources_reserve(&pool, &suspended) == 0,
          "a suspended child reserves both guest ranges before resume");
    CHECK(suspended.slot != timer.slot &&
              win32_guest_thread_resources_reserve(&pool, &next) == 0 &&
              next.slot != suspended.slot && next.slot != timer.slot,
          "pending suspended resources are not handed to another child");
    /* Production calls the same release helper if pthread_create fails. */
    CHECK(win32_guest_thread_resources_release_failed_start(&pool, &suspended) == 0,
          "failed host start releases its never-used guest reservation");
    CHECK(!suspended.active,
          "failed reservation is no longer marked as pending");
    CHECK(win32_guest_thread_resources_reserve(&pool, &replacement) == 0 &&
              replacement.slot == suspended.slot,
          "a failed, never-started slot is reusable");

    failed = next;
    failed.stack_low++;
    CHECK(win32_guest_thread_resources_release_failed_start(&pool, &failed) == EINVAL,
          "release rejects a mismatched reservation instead of freeing another slot");
    CHECK(win32_guest_thread_resources_release_failed_start(&pool, &next) == 0,
          "the exact reservation can be released after host creation failure");
    CHECK(win32_guest_thread_resources_release_failed_start(&pool, &suspended) == EINVAL,
          "double release is rejected");
    CHECK(win32_guest_thread_resources_reserve(&pool, &after) == 0 &&
              after.slot == next.slot,
          "a rejected stale release did not free the replacement reservation");
    return 0;
}

typedef struct ClaimRace {
    pthread_mutex_t *lock;
    void **pending;
    int *started;
    int resume;
    void *claimed;
} ClaimRace;

static void *claim_race_worker(void *opaque) {
    ClaimRace *race = (ClaimRace*)opaque;
    pthread_mutex_lock(race->lock);
    race->claimed = race->resume
        ? win32_guest_thread_claim_resume(race->pending, race->started)
        : win32_guest_thread_claim_close(race->pending, race->started);
    pthread_mutex_unlock(race->lock);
    return 0;
}

static int test_pending_ownership_race(void) {
    Win32GuestThreadResourcePool pool = {0};
    win32_guest_thread_resources_init(&pool);

    for (int attempt = 0; attempt < 64; ++attempt) {
        int token = attempt;
        void *pending = &token;
        int started = 0;
        Win32GuestThreadReservation reservation;
        pthread_mutex_t lock;
        ClaimRace resume = { &lock, &pending, &started, 1, 0 };
        ClaimRace close = { &lock, &pending, &started, 0, 0 };
        pthread_t resume_thread, close_thread;

        CHECK(pthread_mutex_init(&lock, 0) == 0,
              "pending ownership race lock initializes");
        CHECK(win32_guest_thread_resources_reserve(&pool, &reservation) == 0,
              "a pending thread owns its resource pair before the race");
        int rc = pthread_create(&resume_thread, 0, claim_race_worker, &resume);
        CHECK(rc == 0, "resume race worker starts");
        rc = pthread_create(&close_thread, 0, claim_race_worker, &close);
        if (rc != 0) {
            (void)pthread_join(resume_thread, 0);
            fprintf(stderr, "FAIL %s:%d: close race worker starts\n", __FILE__, __LINE__);
            return 1;
        }
        CHECK(pthread_join(resume_thread, 0) == 0,
              "resume claimant joins");
        CHECK(pthread_join(close_thread, 0) == 0,
              "close claimant joins");
        CHECK((resume.claimed == &token) != (close.claimed == &token),
              "exactly one of ResumeThread or CloseHandle owns the pending TArg");
        CHECK(pending == 0,
              "the winning claim clears the shared pending pointer");
        CHECK(started == (resume.claimed == &token),
              "only ResumeThread marks the host worker as launching");
        CHECK(win32_guest_thread_resources_release_failed_start(
                  &pool, &reservation) == 0,
              "close or simulated host-start failure releases the unstarted pair");
        CHECK(pthread_mutex_destroy(&lock) == 0,
              "pending ownership race lock is quiescent");
    }
    return 0;
}

static int test_completed_worker_reuse(void) {
    Win32GuestThreadResourcePool pool = {0};
    Win32GuestThreadReservation running, other, reused;
    win32_guest_thread_resources_init(&pool);
    CHECK(win32_guest_thread_resources_reserve(&pool, &running) == 0,
          "a running worker holds its resource pair");
    CHECK(win32_guest_thread_resources_reserve(&pool, &other) == 0 &&
              other.slot != running.slot,
          "active workers never share a TEB or guest stack");
    /* Production reaches release_quiesced only after dispatch completes and
     * guest_unlock (including its longjmp cleanup) has finished. */
    CHECK(win32_guest_thread_resources_release_quiesced(&pool, &running) == 0,
          "a completed CPU worker can release its quiescent pair");
    CHECK(win32_guest_thread_resources_reserve(&pool, &reused) == 0 &&
              reused.slot == running.slot,
          "only the completed worker slot is available for reuse");
    return 0;
}

int main(void) {
    CHECK(WIN32_GUEST_THREAD_TEB_BASE >= UINT32_C(0x00930000),
          "TEB pool begins after the rounded image end");
    CHECK(WIN32_GUEST_THREAD_TEB_LIMIT < UINT32_C(0x10000000),
          "TEB pool ends before the legacy Win32 heap");
    CHECK(WIN32_GUEST_THREAD_STACK_BASE >= UINT32_C(0x60100000),
          "stack pool begins after COM buffer guard padding");
    CHECK(WIN32_GUEST_THREAD_STACK_LIMIT == UINT32_C(0x7f000000),
          "stack pool stops at the primary guest stack");
    CHECK(WIN32_GUEST_THREAD_TEB_SIZE == UINT32_C(0x2000),
          "legacy TEB reservation size remains 8 KiB");
    CHECK(WIN32_GUEST_THREAD_SLOT_COUNT == 495u,
          "child and timer reservations share the exact bounded capacity");
    CHECK(test_full_capacity() == 0, "full-capacity regression");
    CHECK(test_suspended_and_failed_start() == 0,
          "suspended and failed-start regression");
    CHECK(test_pending_ownership_race() == 0,
          "pending ResumeThread and CloseHandle ownership race");
    CHECK(test_completed_worker_reuse() == 0,
          "completed worker resource reuse");
    puts("PASS Win32 guest thread resource reservations");
    return 0;
}
