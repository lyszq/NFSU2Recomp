#ifndef NFSU2_GUEST_EXECUTION_H
#define NFSU2_GUEST_EXECUTION_H
#include "guest_dispatch.h"
#include "guest_pe.h"

#define GUEST_IMPORT_BASE UINT32_C(0xf0000000)
typedef struct GuestImport {
    uint32_t iat;
    const char *library, *name;
} GuestImport;
enum GuestStop {
    GUEST_STOP_RETURN = 1, GUEST_STOP_IMPORT, GUEST_STOP_UNRESOLVED,
    GUEST_STOP_INSTRUCTION, GUEST_STOP_MEMORY, GUEST_STOP_BUDGET,
    GUEST_STOP_DEPTH, GUEST_STOP_TIMEOUT
};
typedef struct GuestExecutionResult {
    enum GuestStop stop;
    uint32_t ip, target, import_index;
    uint64_t instructions, calls, trace_hash;
    uint32_t maximum_depth;
    CPU cpu;
} GuestExecutionResult;
typedef struct GuestExecutionConfig {
    const GuestDispatch *dispatch;
    const GuestImport *imports;
    uint32_t import_count, instruction_budget, depth_limit;
    uint64_t timeout_ns;
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
void guest_execution_step(CPU *cpu, uint32_t ip);
void guest_execution_unsupported(CPU *cpu, uint32_t ip, const char *mnemonic);
void *guest_execution_pointer(uint32_t address, size_t size);
#endif
