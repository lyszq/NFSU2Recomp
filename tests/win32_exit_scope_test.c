#include "cpu.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

int g_exit_code;
#include "../runtime/win32_exit_scope.inc"

enum { EXPECTED_PROCESS_EXIT_CODE = 0x4C };
static _Atomic int idle_worker_ready;
static _Atomic int idle_worker_stopped;

static void await_flag(_Atomic int *flag){
    for (int attempt = 0; attempt < 5000; ++attempt){
        if (atomic_load_explicit(flag, memory_order_acquire)) return;
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    assert(!"idle worker checkpoint timed out");
}

static void *exit_thread_child(void *unused){
    (void)unused;
    jmp_buf scope;
    void * volatile previous = win32_exit_scope_enter(&scope);
    int exit_kind = setjmp(scope);
    if (exit_kind == 0) win32_exit_thread(77);
    assert(exit_kind == 2);
    assert(win32_exit_thread_status() == 77);
    assert(g_exit_code == 0); /* ExitThread must not rewrite process status. */
    win32_exit_scope_leave((void *)previous);
    return (void *)(uintptr_t)exit_kind;
}

static void *process_exit_child(void *unused){
    (void)unused;
    jmp_buf scope;
    void * volatile previous = win32_exit_scope_enter(&scope);
    int exit_kind = setjmp(scope);
    if (exit_kind == 0) win32_request_process_exit(EXPECTED_PROCESS_EXIT_CODE);
    assert(exit_kind == 1);
    assert(g_exit_code == EXPECTED_PROCESS_EXIT_CODE);
    win32_exit_scope_leave((void *)previous);
    return (void *)(uintptr_t)exit_kind;
}

/* Models the timer worker's sleep/checkpoint boundary when there are no due
 * callbacks to dispatch. The actual production helper owns both operations. */
static void *idle_timer_worker(void *unused){
    (void)unused;
    jmp_buf scope;
    void * volatile previous = win32_exit_scope_enter(&scope);
    int exit_kind = setjmp(scope);
    if (exit_kind == 0){
        atomic_store_explicit(&idle_worker_ready, 1, memory_order_release);
        for (;;){
            struct timespec ts = {0, 1000000L};
            nanosleep(&ts, NULL);
            win32_exit_checkpoint(NULL);
        }
    }
    assert(exit_kind == 1);
    atomic_store_explicit(&idle_worker_stopped, 1, memory_order_release);
    win32_exit_scope_leave((void *)previous);
    return (void *)(uintptr_t)exit_kind;
}

int main(void){
    win32_exit_reset();

    jmp_buf primary_scope;
    void * volatile previous = NULL;
    volatile int reached_primary_checkpoint = 0;
    int exit_kind = setjmp(primary_scope);
    if (exit_kind == 0){
        previous = win32_exit_scope_enter(&primary_scope);
        assert(!win32_exit_requested());

        /* ExitThread in a child may unwind only that child's host stack. */
        pthread_t thread;
        assert(pthread_create(&thread, NULL, exit_thread_child, NULL) == 0);
        void *thread_result = NULL;
        assert(pthread_join(thread, &thread_result) == 0);
        assert((uintptr_t)thread_result == 2);
        assert(g_exit_code == 0);

        /* A timer worker with no callback due still polls its own exit scope. */
        pthread_t idle_thread;
        assert(pthread_create(&idle_thread, NULL, idle_timer_worker, NULL) == 0);
        await_flag(&idle_worker_ready);

        /* ExitProcess captures its code and unwinds its caller's scope. The
         * idle worker sees the request at its next polling checkpoint. */
        pthread_t process_thread;
        assert(pthread_create(&process_thread, NULL, process_exit_child, NULL) == 0);
        void *process_result = NULL;
        assert(pthread_join(process_thread, &process_result) == 0);
        assert((uintptr_t)process_result == 1);
        assert(win32_exit_requested());
        assert(g_exit_code == EXPECTED_PROCESS_EXIT_CODE);

        void *idle_result = NULL;
        await_flag(&idle_worker_stopped);
        assert(pthread_join(idle_thread, &idle_result) == 0);
        assert((uintptr_t)idle_result == 1);
        assert(atomic_load_explicit(&idle_worker_stopped, memory_order_acquire));

        reached_primary_checkpoint = 1;
        win32_exit_checkpoint(NULL);
    }

    assert(exit_kind == 1);
    assert(reached_primary_checkpoint);
    assert(g_exit_code == EXPECTED_PROCESS_EXIT_CODE);
    win32_exit_scope_leave((void *)previous);
    puts("PASS | legacy Win32 exit scopes | child-local ExitThread/ExitProcess, retained code, primary checkpoint");
    return 0;
}
