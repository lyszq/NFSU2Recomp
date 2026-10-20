#include "guest_execution.h"
#include "guest_memory.h"
#include <errno.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct Execution {
    GuestExecutionConfig config;
    GuestExecutionResult result;
    CPU *cpu;
    jmp_buf escape;
    uint64_t started;
    uint32_t depth;
} Execution;
static _Thread_local Execution *active;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}
static _Noreturn void stop(enum GuestStop reason, uint32_t target) {
    if (!active) abort(); /* Internal helper use outside run is a programming error. */
    active->result.stop = reason;
    active->result.target = target;
    longjmp(active->escape, 1);
}
int guest_execution_bind_imports(const GuestPEImage *image, const GuestImport *imports,
                                 uint32_t count) {
    if (!image || (count && !imports) || count > 4096) return EINVAL;
    uint64_t end = (uint64_t)image->image_base + image->image_size;
    if (!image->image_size || end > GUEST_MEMORY_SIZE) return EINVAL;
    for (uint32_t i = 0; i < count; ++i) {
        if (!imports[i].library || !imports[i].name ||
            imports[i].iat < image->image_base || (uint64_t)imports[i].iat + 4 > end ||
            !guest_memory_pointer(imports[i].iat, 4, 1)) return EINVAL;
        for (uint32_t j = 0; j < i; ++j) {
            uint64_t a = imports[i].iat, b = imports[j].iat;
            if (a < b + 4 && b < a + 4) return EEXIST;
        }
    }
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t target = GUEST_IMPORT_BASE + i;
        memcpy(g_mem + imports[i].iat, &target, 4);
    }
    return 0;
}
void guest_execution_call(CPU *cpu, uint32_t target) {
    if (!active || cpu != active->cpu) abort();
    active->result.calls++;
    if (target >= GUEST_IMPORT_BASE) {
        uint32_t index = target - GUEST_IMPORT_BASE;
        if (index < active->config.import_count) {
            active->result.import_index = index;
            if (active->config.import_handler) {
                uint32_t fault = 0;
                int handled = active->config.import_handler(cpu, &active->config.imports[index],
                    active->config.import_context, &fault);
                if (handled < 0) stop(GUEST_STOP_MEMORY, fault);
                if (handled > 0) { active->result.imports_handled++; return; }
            }
            stop(GUEST_STOP_IMPORT, target);
        }
        stop(GUEST_STOP_UNRESOLVED, target);
    }
    GuestFunction function = guest_dispatch_lookup(active->config.dispatch, target);
    if (!function) stop(GUEST_STOP_UNRESOLVED, target);
    if (active->depth >= active->config.depth_limit) stop(GUEST_STOP_DEPTH, target);
    active->depth++;
    if (active->depth > active->result.maximum_depth)
        active->result.maximum_depth = active->depth;
    function(cpu);
    active->depth--;
}
void guest_execution_step(CPU *cpu, uint32_t ip) {
    if (!active || cpu != active->cpu) abort();
    active->result.ip = ip;
    cpu->eip = ip;
    if (active->result.instructions >= active->config.instruction_budget)
        stop(GUEST_STOP_BUDGET, ip);
    if (!(active->result.instructions & 255u) &&
        monotonic_ns() - active->started >= active->config.timeout_ns)
        stop(GUEST_STOP_TIMEOUT, ip);
    active->result.instructions++;
    active->result.trace_hash ^= ip;
    active->result.trace_hash *= UINT64_C(1099511628211);
}
void guest_execution_unsupported(CPU *cpu, uint32_t ip, const char *mnemonic) {
    (void)mnemonic;
    if (!active || cpu != active->cpu) abort();
    active->result.ip = ip;
    stop(GUEST_STOP_INSTRUCTION, ip);
}
void *guest_execution_pointer(uint32_t address, size_t size) {
    if (!active) abort();
    /* All probe image/stack pages are RW; require writable whole-range access
     * for typed lvalues so a generated write cannot bypass core permissions. */
    void *pointer = guest_memory_pointer(address, size, 1);
    if (!pointer) stop(GUEST_STOP_MEMORY, address);
    return pointer;
}
int guest_execution_run(const GuestExecutionConfig *config, CPU *cpu, uint32_t entry,
                         GuestExecutionResult *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof *result);
    if (!config || !cpu || !config->dispatch || !config->instruction_budget ||
        !config->depth_limit || config->depth_limit > 128 || !config->timeout_ns ||
        config->import_count > 4096 || (config->import_count && !config->imports)) return EINVAL;
    if (active) return EBUSY;
    for (uint32_t i=0;i<config->import_count;i++)
        if (!config->imports[i].library || !config->imports[i].name) return EINVAL;
    Execution *execution = calloc(1, sizeof *execution);
    if (!execution) return ENOMEM;
    execution->config = *config;
    execution->cpu = cpu;
    execution->result.trace_hash = UINT64_C(14695981039346656037);
    execution->started = monotonic_ns();
    if (!execution->started) { free(execution); return EIO; }
    active = execution;
    if (!setjmp(execution->escape)) {
        guest_execution_call(cpu, entry);
        execution->result.stop = GUEST_STOP_RETURN;
    }
    execution->result.cpu = *cpu;
    *result = execution->result;
    active = NULL;
    free(execution);
    return 0;
}
