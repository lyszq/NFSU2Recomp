#include "guest_execution.h"
#include "guest_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
        return 1; \
    } \
} while (0)

enum {
    TEXT_BASE = 0x00400000u,
    TEXT_SIZE = 0x1000u,
    STACK_BASE = 0x00100000u,
    STACK_TOP = 0x00110000u,
    RET_TOP = 0x13572468u,
    RET_AFTER_CALL = 0x24681357u,
    IMPORT_ARG = 0xabcdef01u,
    IMPORT_RETURN_EAX = 0x76543210u,
    MEMORY_FAULT = 0xdeadf00du,
    API_STATE_FAULT = 0xa11ce001u,
    MISSING_NATIVE_TARGET = 0x00500000u,
    LOOP_BUDGET = 20001u,
    IP_ACTUAL_CALLER = TEXT_BASE + 0x10u,
    IP_TAIL_SOURCE = TEXT_BASE + 0x20u,
    IP_TAIL_NATIVE = TEXT_BASE + 0x30u,
    IP_TAIL_LOOP = TEXT_BASE + 0x40u,
    IP_DEPTH_OWNER = TEXT_BASE + 0x50u,
    IP_DEPTH_TARGET = TEXT_BASE + 0x60u,
    IP_TAIL_IMPORT = TEXT_BASE + 0x70u,
    IP_TAIL_UNKNOWN_IMPORT = TEXT_BASE + 0x80u,
    IP_TAIL_MISSING = TEXT_BASE + 0x90u
};

enum ImportOutcome {
    IMPORT_COMPLETE,
    IMPORT_MEMORY_FAILURE,
    IMPORT_API_STATE_FAILURE,
    IMPORT_UNSUPPORTED
};

typedef struct ImportProbe {
    enum ImportOutcome outcome;
    uint32_t calls, esp, return_ip, argument;
    int frame_ok;
} ImportProbe;

static GuestDispatch dispatch;
static const GuestImport imports[] = {
    { 0, "synthetic.dll", "SyntheticStdcall" }
};
static uint32_t loop_transfers;
static uint32_t after_nested_call;
static uint32_t after_depth_target;
static int nested_return_ok;

static void store_u32(uint32_t address, uint32_t value) {
    memcpy(g_mem + address, &value, sizeof value);
}

static uint32_t load_u32(uint32_t address) {
    uint32_t value;
    memcpy(&value, g_mem + address, sizeof value);
    return value;
}

static void push_return(CPU *cpu, uint32_t return_ip) {
    cpu->esp -= 4u;
    store_u32(cpu->esp, return_ip);
}

static void pop_return(CPU *cpu) {
    cpu->eip = load_u32(cpu->esp);
    cpu->esp += 4u;
}

static void prepare_cpu(CPU *cpu) {
    memset(cpu, 0, sizeof *cpu);
    cpu->esp = STACK_TOP;
    push_return(cpu, RET_TOP);
}

/* The entry has a stdcall frame: return IP followed by one guest argument. */
static void prepare_cpu_with_import_frame(CPU *cpu) {
    memset(cpu, 0, sizeof *cpu);
    cpu->esp = STACK_TOP;
    cpu->esp -= 4u;
    store_u32(cpu->esp, IMPORT_ARG);
    push_return(cpu, RET_TOP);
}

static GuestExecutionConfig make_config(uint32_t instruction_budget,
                                        uint32_t depth_limit) {
    GuestExecutionConfig config = {
        .dispatch = &dispatch,
        .imports = imports,
        .import_count = (uint32_t)(sizeof imports / sizeof imports[0]),
        .instruction_budget = instruction_budget,
        .depth_limit = depth_limit,
        .timeout_ns = UINT64_C(60000000000)
    };
    return config;
}

static int run_expect(GuestExecutionConfig *config, CPU *cpu, uint32_t entry,
                      enum GuestStop expected_stop, GuestExecutionResult *result) {
    int rc = guest_execution_run(config, cpu, entry, result);
    if (rc != 0) {
        fprintf(stderr, "FAIL entry 0x%08x: expected run rc 0, got %d\n", entry, rc);
        return 1;
    }
    if (result->stop != expected_stop) {
        fprintf(stderr, "FAIL entry 0x%08x: expected stop %d, got %d\n",
                entry, (int)expected_stop, (int)result->stop);
        return 1;
    }
    return 0;
}

static void fn_actual_caller(CPU *cpu) {
    guest_execution_step(cpu, IP_ACTUAL_CALLER);
    push_return(cpu, RET_AFTER_CALL);
    guest_execution_call(cpu, IP_TAIL_SOURCE);
    nested_return_ok = cpu->eip == RET_AFTER_CALL &&
                       cpu->esp == STACK_TOP - 4u &&
                       cpu->eax == IMPORT_RETURN_EAX;
    after_nested_call++;
    pop_return(cpu);
}

static void fn_tail_source(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_SOURCE);
    guest_execution_tail(cpu, IP_TAIL_NATIVE);
    return;
}

static void fn_tail_native(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_NATIVE);
    cpu->eax = IMPORT_RETURN_EAX;
    pop_return(cpu);
}

static void fn_tail_loop(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_LOOP);
    loop_transfers++;
    guest_execution_tail(cpu, IP_TAIL_LOOP);
    return;
}

static void fn_depth_owner(CPU *cpu) {
    guest_execution_step(cpu, IP_DEPTH_OWNER);
    push_return(cpu, RET_AFTER_CALL);
    guest_execution_call(cpu, IP_DEPTH_TARGET);
    after_depth_target++;
    pop_return(cpu);
}

static void fn_depth_target(CPU *cpu) {
    guest_execution_step(cpu, IP_DEPTH_TARGET);
    pop_return(cpu);
}

static void fn_tail_import(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_IMPORT);
    guest_execution_tail(cpu, GUEST_IMPORT_BASE);
    return;
}

static void fn_tail_unknown_import(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_UNKNOWN_IMPORT);
    guest_execution_tail(cpu, GUEST_IMPORT_BASE + 7u);
    return;
}

static void fn_tail_missing(CPU *cpu) {
    guest_execution_step(cpu, IP_TAIL_MISSING);
    guest_execution_tail(cpu, MISSING_NATIVE_TARGET);
    return;
}

static int synthetic_import_handler(CPU *cpu, const GuestImport *import,
                                    void *context, uint32_t *fault) {
    ImportProbe *probe = (ImportProbe *)context;
    probe->calls++;
    probe->esp = cpu->esp;
    probe->return_ip = load_u32(cpu->esp);
    probe->argument = load_u32(cpu->esp + 4u);
    probe->frame_ok = import &&
                      strcmp(import->library, "synthetic.dll") == 0 &&
                      strcmp(import->name, "SyntheticStdcall") == 0 &&
                      cpu->esp == STACK_TOP - 8u &&
                      probe->return_ip == RET_TOP &&
                      probe->argument == IMPORT_ARG;

    switch (probe->outcome) {
    case IMPORT_COMPLETE:
        cpu->eax = IMPORT_RETURN_EAX;
        pop_return(cpu);
        cpu->esp += 4u; /* stdcall callee removes the argument */
        return 1;
    case IMPORT_MEMORY_FAILURE:
        *fault = MEMORY_FAULT;
        return -1;
    case IMPORT_API_STATE_FAILURE:
        *fault = API_STATE_FAULT;
        return -2;
    case IMPORT_UNSUPPORTED:
        return 0;
    }
    return 0;
}

static const uint32_t function_addresses[] = {
    IP_ACTUAL_CALLER, IP_TAIL_SOURCE, IP_TAIL_NATIVE, IP_TAIL_LOOP,
    IP_DEPTH_OWNER, IP_DEPTH_TARGET, IP_TAIL_IMPORT,
    IP_TAIL_UNKNOWN_IMPORT, IP_TAIL_MISSING
};
static const GuestFunction guest_functions[] = {
    fn_actual_caller, fn_tail_source, fn_tail_native, fn_tail_loop,
    fn_depth_owner, fn_depth_target, fn_tail_import,
    fn_tail_unknown_import, fn_tail_missing
};

static int test_short_tail_chain_and_actual_call(void) {
    CPU cpu;
    GuestExecutionResult result;
    GuestExecutionConfig config = make_config(32, 2);

    prepare_cpu(&cpu);
    after_nested_call = 0;
    nested_return_ok = 0;
    CHECK(run_expect(&config, &cpu, IP_ACTUAL_CALLER, GUEST_STOP_RETURN,
                     &result) == 0,
          "an actual nested CALL can finish through a native tail target");
    CHECK(after_nested_call == 1 && nested_return_ok,
          "tail target consumes the existing nested return and resumes its CALL caller");
    CHECK(result.calls == 2 && result.maximum_depth == 2,
          "tail transfer adds no call count or guest depth to the real nested CALL");
    CHECK(result.instructions == 3 && result.ip == IP_TAIL_NATIVE &&
          result.trace_hash == UINT64_C(0xe452cb60082b9ab7),
          "short CALL/tail/native chain has the exact three-IP trace");
    CHECK(cpu.eip == RET_TOP && cpu.esp == STACK_TOP &&
          cpu.eax == IMPORT_RETURN_EAX,
          "tail target returns through the actual caller to the original entry return");
    CHECK(result.cpu.eip == cpu.eip && result.cpu.esp == cpu.esp,
          "execution result snapshots the final tail-chain CPU state");
    return 0;
}

static int test_tail_at_depth_limit_and_nested_call_refusal(void) {
    CPU cpu;
    GuestExecutionResult result;
    GuestExecutionConfig config = make_config(32, 1);

    prepare_cpu(&cpu);
    CHECK(run_expect(&config, &cpu, IP_TAIL_SOURCE, GUEST_STOP_RETURN,
                     &result) == 0,
          "tail target is allowed when the guest depth limit is one");
    CHECK(result.calls == 1 && result.maximum_depth == 1 &&
          result.instructions == 2,
          "tail target stays within the existing entry call and depth");
    CHECK(cpu.eip == RET_TOP && cpu.esp == STACK_TOP,
          "depth-limit tail target consumes the existing entry return");

    prepare_cpu(&cpu);
    after_depth_target = 0;
    CHECK(run_expect(&config, &cpu, IP_DEPTH_OWNER, GUEST_STOP_DEPTH,
                     &result) == 0,
          "a real nested CALL still observes the depth limit");
    CHECK(result.target == IP_DEPTH_TARGET && result.calls == 2 &&
          result.maximum_depth == 1 && after_depth_target == 0,
          "depth stop counts the attempted nested CALL without entering its target");
    CHECK(result.ip == IP_DEPTH_OWNER && cpu.eip == IP_DEPTH_OWNER &&
          cpu.esp == STACK_TOP - 8u && load_u32(cpu.esp) == RET_AFTER_CALL &&
          load_u32(STACK_TOP - 4u) == RET_TOP,
          "depth refusal preserves the caller instruction and both return words");
    return 0;
}

static int test_long_tail_cycle_is_budgeted_iteratively(void) {
    CPU cpu;
    GuestExecutionResult result;
    GuestExecutionConfig config = make_config(LOOP_BUDGET, 1);

    prepare_cpu(&cpu);
    loop_transfers = 0;
    CHECK(run_expect(&config, &cpu, IP_TAIL_LOOP, GUEST_STOP_BUDGET,
                     &result) == 0,
          "long tail cycle stops at the instruction budget");
    CHECK(loop_transfers == LOOP_BUDGET &&
          result.instructions == LOOP_BUDGET &&
          result.ip == IP_TAIL_LOOP && cpu.eip == IP_TAIL_LOOP,
          "at least twenty thousand tail transfers execute before the budget stop");
    CHECK(result.calls == 1 && result.maximum_depth == 1,
          "long tail cycle does not create guest calls or guest depth");
    CHECK(cpu.esp == STACK_TOP - 4u && load_u32(cpu.esp) == RET_TOP,
          "tail cycle never pushes guest return addresses");
    return 0;
}

static int run_import_outcome(enum ImportOutcome outcome,
                              enum GuestStop expected_stop,
                              uint32_t expected_target) {
    CPU cpu;
    GuestExecutionResult result;
    ImportProbe probe = { .outcome = outcome };
    GuestExecutionConfig config = make_config(16, 1);
    config.import_handler = synthetic_import_handler;
    config.import_context = &probe;
    prepare_cpu_with_import_frame(&cpu);
    cpu.eax = 0x11223344u;

    CHECK(run_expect(&config, &cpu, IP_TAIL_IMPORT, expected_stop, &result) == 0,
          "tail transfer to a known import has the expected outcome");
    CHECK(probe.calls == 1 && probe.frame_ok &&
          probe.esp == STACK_TOP - 8u && probe.return_ip == RET_TOP &&
          probe.argument == IMPORT_ARG,
          "import handler sees the same return and stdcall argument frame");
    CHECK(result.calls == 1 && result.maximum_depth == 1 &&
          result.instructions == 1 && result.ip == IP_TAIL_IMPORT &&
          result.target == expected_target,
          "tail import records its stop without adding a call or depth");

    if (outcome == IMPORT_COMPLETE) {
        CHECK(result.imports_handled == 1 && cpu.eax == IMPORT_RETURN_EAX &&
              cpu.eip == RET_TOP && cpu.esp == STACK_TOP,
              "successful import performs stdcall cleanup and returns normally");
    } else {
        CHECK(result.imports_handled == 0 && cpu.eax == 0x11223344u &&
              cpu.eip == IP_TAIL_IMPORT && cpu.esp == STACK_TOP - 8u &&
              load_u32(cpu.esp) == RET_TOP &&
              load_u32(cpu.esp + 4u) == IMPORT_ARG,
              "failed or unsupported import preserves the guest stdcall frame");
    }
    return 0;
}

static int test_tail_import_outcomes_and_unknown_tag(void) {
    CPU cpu;
    GuestExecutionResult result;
    ImportProbe probe = { .outcome = IMPORT_UNSUPPORTED };
    GuestExecutionConfig config;

    CHECK(run_import_outcome(IMPORT_COMPLETE, GUEST_STOP_RETURN, 0) == 0,
          "tail import success case passes");
    CHECK(run_import_outcome(IMPORT_MEMORY_FAILURE, GUEST_STOP_MEMORY,
                             MEMORY_FAULT) == 0,
          "tail import memory-failure case passes");
    CHECK(run_import_outcome(IMPORT_API_STATE_FAILURE, GUEST_STOP_API_STATE,
                             API_STATE_FAULT) == 0,
          "tail import API-state-failure case passes");
    CHECK(run_import_outcome(IMPORT_UNSUPPORTED, GUEST_STOP_IMPORT,
                             GUEST_IMPORT_BASE) == 0,
          "tail import unsupported case passes");

    config = make_config(16, 1);
    config.import_handler = synthetic_import_handler;
    config.import_context = &probe;
    prepare_cpu_with_import_frame(&cpu);
    CHECK(run_expect(&config, &cpu, IP_TAIL_UNKNOWN_IMPORT,
                     GUEST_STOP_UNRESOLVED, &result) == 0,
          "unknown import tag reached by a tail transfer is unresolved");
    CHECK(result.target == GUEST_IMPORT_BASE + 7u && result.calls == 1 &&
          result.maximum_depth == 1 && result.ip == IP_TAIL_UNKNOWN_IMPORT &&
          probe.calls == 0,
          "unknown tag preserves its target and does not call the import handler");
    CHECK(cpu.eip == IP_TAIL_UNKNOWN_IMPORT && cpu.esp == STACK_TOP - 8u &&
          load_u32(cpu.esp) == RET_TOP &&
          load_u32(cpu.esp + 4u) == IMPORT_ARG,
          "unknown import leaves the interrupted stdcall frame intact");
    return 0;
}

static int test_tail_to_missing_native_target_preserves_context(void) {
    CPU cpu;
    GuestExecutionResult result;
    GuestExecutionConfig config = make_config(16, 1);

    prepare_cpu(&cpu);
    cpu.eax = 0x55667788u;
    CHECK(run_expect(&config, &cpu, IP_TAIL_MISSING, GUEST_STOP_UNRESOLVED,
                     &result) == 0,
          "missing native target reached by tail transfer is unresolved");
    CHECK(result.target == MISSING_NATIVE_TARGET && result.ip == IP_TAIL_MISSING &&
          result.calls == 1 && result.maximum_depth == 1,
          "missing target stop preserves the source IP, target, and one entry call");
    CHECK(cpu.eip == IP_TAIL_MISSING && cpu.eax == 0x55667788u &&
          cpu.esp == STACK_TOP - 4u && load_u32(cpu.esp) == RET_TOP,
          "missing target preserves CPU registers and the existing return address");
    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0, "guest memory mapping initializes");
    CHECK(guest_memory_commit(STACK_BASE, STACK_TOP - STACK_BASE) == 0,
          "synthetic guest stack commits");
    CHECK(guest_dispatch_init(&dispatch, TEXT_BASE, TEXT_SIZE,
                              function_addresses, guest_functions,
                              (uint32_t)(sizeof function_addresses /
                                         sizeof function_addresses[0])) == 0,
          "synthetic function dispatch table initializes");

    CHECK(test_short_tail_chain_and_actual_call() == 0,
          "short tail chain and actual CALL contract pass");
    CHECK(test_tail_at_depth_limit_and_nested_call_refusal() == 0,
          "tail-at-limit and nested-call depth behavior pass");
    CHECK(test_long_tail_cycle_is_budgeted_iteratively() == 0,
          "long tail cycle terminates iteratively at its budget");
    CHECK(test_tail_import_outcomes_and_unknown_tag() == 0,
          "tail imports preserve outcomes and unknown tags");
    CHECK(test_tail_to_missing_native_target_preserves_context() == 0,
          "missing tail target preserves diagnostic context");

    guest_dispatch_destroy(&dispatch);
    CHECK(guest_memory_shutdown() == 0, "guest memory mapping shuts down");
    puts("PASS guest execution tail core");
    return 0;
}
