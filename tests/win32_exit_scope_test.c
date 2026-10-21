#include "cpu.h"
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

int g_exit_code;
#include "../runtime/win32_exit_scope.inc"

enum { EXPECTED_PROCESS_EXIT_CODE = 0x4C };

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

int main(void){
    win32_exit_reset();

    jmp_buf primary_scope;
    void * volatile previous = NULL;
    volatile int reached_primary_checkpoint = 0;
    int exit_kind = setjmp(primary_scope);
    if (exit_kind == 0){
        previous = win32_exit_scope_enter(&primary_scope);

        /* ExitThread in a child may unwind only that child's host stack. */
        pthread_t thread;
        assert(pthread_create(&thread, NULL, exit_thread_child, NULL) == 0);
        void *thread_result = NULL;
        assert(pthread_join(thread, &thread_result) == 0);
        assert((uintptr_t)thread_result == 2);
        assert(g_exit_code == 0);

        /* ExitProcess captures its code, unwinds the child, then the primary
         * observes it at its own runtime checkpoint and catches its own jump. */
        assert(pthread_create(&thread, NULL, process_exit_child, NULL) == 0);
        void *process_result = NULL;
        assert(pthread_join(thread, &process_result) == 0);
        assert((uintptr_t)process_result == 1);
        assert(g_exit_code == EXPECTED_PROCESS_EXIT_CODE);

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
