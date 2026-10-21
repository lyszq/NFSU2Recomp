#ifndef NFSU2_GUEST_EXECUTION_H
#define NFSU2_GUEST_EXECUTION_H
#include "guest_dispatch.h"
#include "guest_pe.h"

#define GUEST_IMPORT_BASE UINT32_C(0xf0000000)
typedef struct GuestImport {
    uint32_t iat;
    const char *library, *name;
} GuestImport;
/* 1 = completed stdcall, 0 = unsupported without side effects, -1 = memory
 * fault (address returned through fault), -2 = invalid/unsupported host state.
 * Handler validates before mutation; failed calls keep their guest call frame. */
typedef int (*GuestImportHandler)(CPU *, const GuestImport *, void *, uint32_t *fault);
enum GuestStop {
    GUEST_STOP_RETURN = 1, GUEST_STOP_IMPORT, GUEST_STOP_UNRESOLVED,
    GUEST_STOP_INSTRUCTION, GUEST_STOP_MEMORY, GUEST_STOP_BUDGET,
    GUEST_STOP_DEPTH, GUEST_STOP_TIMEOUT, GUEST_STOP_API_STATE
};
typedef struct GuestExecutionResult {
    enum GuestStop stop;
    uint32_t ip, target, import_index;
    uint64_t instructions, calls, trace_hash, imports_handled;
    uint32_t maximum_depth;
    CPU cpu;
    /* Explicit per-run virtual TSC diagnostics. The hash folds each stepped
     * RDTSC IP then its returned 64-bit value using the FNV-1a word rule. */
    uint64_t virtual_tsc_next, virtual_tsc_reads, virtual_tsc_hash;
} GuestExecutionResult;
typedef struct GuestExecutionConfig {
    const GuestDispatch *dispatch;
    const GuestImport *imports;
    uint32_t import_count, instruction_budget, depth_limit;
    uint64_t timeout_ns;
    GuestImportHandler import_handler;
    void *import_context;
    /* Explicit virtual RDTSC fixture. A zero increment is unconfigured and
     * leaves the RDTSC helper unsupported at its stepped instruction. */
    uint64_t virtual_tsc_initial, virtual_tsc_increment;
} GuestExecutionConfig;

/* Validate every IAT slot before writing any. Uses the upstream 0xF... tag
 * scheme; this binds imports without pretending to implement any host API. */
int guest_execution_bind_imports(const GuestPEImage *image, const GuestImport *imports,
                                 uint32_t count);
/* Runs static native functions only. An explicit stop is a result, NOT engine
 * success. No missing call/instruction is swallowed and no guest bytes execute
 * as host code. Caller serializes the singleton mapping lifecycle. State/memory
 * at a stop are preserved for diagnostics, not rollback or automatic resume.
 */
int guest_execution_run(const GuestExecutionConfig *config, CPU *cpu, uint32_t entry,
                         GuestExecutionResult *result);
void guest_execution_call(CPU *cpu, uint32_t target);
/* Records an x86 tail transfer. Generated code must return immediately after
 * this call; the enclosing dispatch loop runs the target at the same guest
 * call depth and without pushing a synthetic return address. */
void guest_execution_tail(CPU *cpu, uint32_t target);
void guest_execution_step(CPU *cpu, uint32_t ip);
/* Uses the per-run virtual TSC only when the config has a nonzero increment;
 * otherwise stops at the current stepped instruction before modifying CPU. */
void guest_execution_rdtsc(CPU *cpu);
void guest_execution_unsupported(CPU *cpu, uint32_t ip, const char *mnemonic);
void *guest_execution_pointer(uint32_t address, size_t size);
#endif
