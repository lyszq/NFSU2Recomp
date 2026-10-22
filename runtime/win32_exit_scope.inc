/*
 * Thread-local setjmp targets and process-wide ExitProcess request state.
 * Included once by win32.c and directly by the focused native regression so
 * the test exercises this implementation without linking the game runtime.
 */
#include <setjmp.h>
#include <stdatomic.h>

static _Thread_local jmp_buf *g_exit_scope;
static _Thread_local int g_thread_exit_code;
/* 0 = no request, 1 = winner publishing g_exit_code, 2 = request visible. */
static _Atomic int g_process_exit_state = 0;

void *win32_exit_scope_enter(jmp_buf *target){
    jmp_buf *previous = g_exit_scope;
    g_exit_scope = target;
    return previous;
}

void win32_exit_scope_leave(void *previous){
    g_exit_scope = (jmp_buf *)previous;
}

void win32_exit_reset(void){
    g_exit_code = 0;
    atomic_store_explicit(&g_process_exit_state, 0, memory_order_release);
}

void win32_request_process_exit(int code){
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(&g_process_exit_state,
                                                &expected, 1,
                                                memory_order_acq_rel,
                                                memory_order_acquire)){
        g_exit_code = code;
        atomic_store_explicit(&g_process_exit_state, 2, memory_order_release);
    } else {
        /* Another thread is publishing the first process exit code. */
        while (atomic_load_explicit(&g_process_exit_state, memory_order_acquire) == 1) {}
    }
    if (g_exit_scope) longjmp(*g_exit_scope, 1);
}

/* Wait loops that temporarily release the guest lock need a non-jumping
 * observation point. They can finish releasing their own locks and restore
 * the GIL before calling win32_exit_checkpoint(). */
int win32_exit_requested(void){
    return atomic_load_explicit(&g_process_exit_state, memory_order_acquire) == 2;
}

/* A child thread that calls ExitProcess cannot jump into the primary worker's
 * stack. Each guest worker observes the request at a transfer boundary and
 * exits through its own scope. */
void win32_exit_checkpoint(CPU *c){
    (void)c;
    if (win32_exit_requested() && g_exit_scope)
        longjmp(*g_exit_scope, 1);
}

/* Returns only when the caller has no armed thread-local exit scope. */
int win32_exit_thread(int code){
    g_thread_exit_code = code;
    if (g_exit_scope) longjmp(*g_exit_scope, 2);
    return 0;
}

int win32_exit_thread_status(void){ return g_thread_exit_code; }
