#include "guest_execution.h"
#include "guest_bootstrap.h"
#include "guest_memory.h"

#include <errno.h>
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
    IMAGE_BASE = 0x00600000u,
    IMAGE_SIZE = 0x8000u,
    CROSS_BASE = 0x00300000u,
    RET_TOP = 0x13572468u,
    RET_NESTED = 0x24681357u,
    ARG_NESTED = 0xabcdef01u,
    IP_ROOT = TEXT_BASE + 0x10u,
    IP_LEAF = TEXT_BASE + 0x20u,
    IP_UNRESOLVED = TEXT_BASE + 0x30u,
    IP_IMPORT = TEXT_BASE + 0x40u,
    IP_UNKNOWN_IMPORT = TEXT_BASE + 0x50u,
    IP_UNSUPPORTED = TEXT_BASE + 0x60u,
    IP_MEMORY = TEXT_BASE + 0x70u,
    IP_BUDGET = TEXT_BASE + 0x80u,
    IP_DEPTH_A = TEXT_BASE + 0x90u,
    IP_DEPTH_B = TEXT_BASE + 0xa0u,
    IP_DEPTH_C = TEXT_BASE + 0xb0u,
    IP_SIMPLE = TEXT_BASE + 0xc0u,
    IP_BUSY = TEXT_BASE + 0xd0u
};

static GuestDispatch dispatch;
static GuestExecutionConfig config;
static GuestExecutionResult nested_result;
static uint32_t import_target;
static int nested_ok;
static int after_stop;
static int after_nested_call;
static int leaf_ran;
static int depth_c_ran;
static int nested_run_rc;

static void store_u32(uint32_t address, uint32_t value) {
    memcpy(g_mem + address, &value, sizeof value);
}

static uint32_t load_u32(uint32_t address) {
    uint32_t value;
    memcpy(&value, g_mem + address, sizeof value);
    return value;
}

static void push_return(CPU *c, uint32_t return_ip) {
    c->esp -= 4u;
    store_u32(c->esp, return_ip);
}

static void pop_return(CPU *c) {
    c->eip = load_u32(c->esp);
    c->esp += 4u;
}

static void fn_leaf(CPU *c) {
    guest_execution_step(c, IP_LEAF);
    leaf_ran++;
    c->eax = 0x76543210u;
    pop_return(c);
    c->esp += 4u; /* ret 4: discard the argument pushed by the caller */
}

static void fn_root(CPU *c) {
    guest_execution_step(c, IP_ROOT);
    c->ebx = 0xb16b00b5u;
    c->esp -= 4u;
    store_u32(c->esp, ARG_NESTED);
    push_return(c, RET_NESTED);
    guest_execution_call(c, IP_LEAF);
    nested_ok = c->eip == RET_NESTED && c->esp == STACK_TOP - 4u &&
                c->eax == 0x76543210u && load_u32(STACK_TOP - 8u) == ARG_NESTED;
    after_nested_call++;
    pop_return(c);
}

static void fn_unresolved_caller(CPU *c) {
    guest_execution_step(c, IP_UNRESOLVED);
    c->ebx = 0x0badc0deu;
    push_return(c, RET_NESTED);
    guest_execution_call(c, 0x00500000u);
    after_stop++;
}

static void fn_import_caller(CPU *c) {
    guest_execution_step(c, IP_IMPORT);
    push_return(c, RET_NESTED);
    guest_execution_call(c, import_target);
    after_stop++;
}

static void fn_unknown_import_caller(CPU *c) {
    guest_execution_step(c, IP_UNKNOWN_IMPORT);
    push_return(c, RET_NESTED);
    guest_execution_call(c, GUEST_IMPORT_BASE + 7u);
    after_stop++;
}

static void fn_unsupported(CPU *c) {
    guest_execution_step(c, IP_UNSUPPORTED);
    guest_execution_unsupported(c, IP_UNSUPPORTED, "synthetic-ud");
    after_stop++;
}

static void fn_memory_crossrange(CPU *c) {
    guest_execution_step(c, IP_MEMORY);
    c->eax = 0x11223344u;
    (void)guest_execution_pointer(CROSS_BASE + GUEST_MEMORY_GRANULE - 2u, 4u);
    after_stop++;
}

static void fn_budget(CPU *c) {
    guest_execution_step(c, IP_BUDGET);
    c->eax++;
    guest_execution_step(c, IP_BUDGET + 1u);
    c->eax++;
    guest_execution_step(c, IP_BUDGET + 2u);
    c->eax++;
    pop_return(c);
}

static void fn_depth_a(CPU *c) {
    guest_execution_step(c, IP_DEPTH_A);
    c->eax = 0xa001u;
    push_return(c, 0xca11a001u);
    guest_execution_call(c, IP_DEPTH_B);
    after_stop++;
}

static void fn_depth_b(CPU *c) {
    guest_execution_step(c, IP_DEPTH_B);
    c->ebx = 0xb002u;
    push_return(c, 0xca11b002u);
    guest_execution_call(c, IP_DEPTH_C);
    after_stop++;
}

static void fn_depth_c(CPU *c) {
    (void)c;
    depth_c_ran++;
}

static void fn_simple(CPU *c) {
    guest_execution_step(c, IP_SIMPLE);
    c->eax = 0x55aa55aau;
    pop_return(c);
}

static void fn_nested_run(CPU *c) {
    guest_execution_step(c, IP_BUSY);
    CPU inner_cpu = { 0 };
    inner_cpu.esp = STACK_TOP;
    nested_run_rc = guest_execution_run(&config, &inner_cpu, IP_SIMPLE,
                                        &nested_result);
    pop_return(c);
}

static const uint32_t function_addresses[] = {
    IP_ROOT, IP_LEAF, IP_UNRESOLVED, IP_IMPORT, IP_UNKNOWN_IMPORT,
    IP_UNSUPPORTED, IP_MEMORY, IP_BUDGET, IP_DEPTH_A, IP_DEPTH_B,
    IP_DEPTH_C, IP_SIMPLE, IP_BUSY
};
static const GuestFunction guest_functions[] = {
    fn_root, fn_leaf, fn_unresolved_caller, fn_import_caller,
    fn_unknown_import_caller, fn_unsupported, fn_memory_crossrange,
    fn_budget, fn_depth_a, fn_depth_b, fn_depth_c, fn_simple, fn_nested_run
};

static void prepare_cpu(CPU *cpu) {
    memset(cpu, 0, sizeof *cpu);
    cpu->esp = STACK_TOP;
    push_return(cpu, RET_TOP);
}

static GuestExecutionConfig make_config(uint32_t instruction_budget,
                                        uint32_t depth_limit,
                                        const GuestImport *imports,
                                        uint32_t import_count) {
    GuestExecutionConfig result = {
        .dispatch = &dispatch,
        .imports = imports,
        .import_count = import_count,
        .instruction_budget = instruction_budget,
        .depth_limit = depth_limit,
        .timeout_ns = UINT64_C(60000000000)
    };
    return result;
}

static int run_expect(GuestExecutionConfig *run_config, CPU *cpu,
                      uint32_t entry, enum GuestStop stop,
                      GuestExecutionResult *result) {
    int rc = guest_execution_run(run_config, cpu, entry, result);
    if (rc != 0) {
        fprintf(stderr, "FAIL run at 0x%08x: expected run rc 0, got %d\n",
                entry, rc);
        return 1;
    }
    if (result->stop != stop) {
        fprintf(stderr, "FAIL run at 0x%08x: expected stop %d, got %d\n",
                entry, (int)stop, (int)result->stop);
        return 1;
    }
    return 0;
}

static int test_nested_call_and_stack_contract(void) {
    CPU cpu;
    GuestExecutionResult result;
    config = make_config(32, 8, NULL, 0);
    prepare_cpu(&cpu);
    nested_ok = 0;
    after_nested_call = 0;
    leaf_ran = 0;

    CHECK(run_expect(&config, &cpu, IP_ROOT, GUEST_STOP_RETURN, &result) == 0,
          "nested native call returns normally");
    CHECK(nested_ok && after_nested_call == 1 && leaf_ran == 1,
          "nested callee returns through its pushed return and ret-4 cleanup");
    CHECK(result.calls == 2 && result.maximum_depth == 2,
          "entry and nested target are counted with nested depth");
    CHECK(result.instructions == 2 && result.ip == IP_LEAF,
          "both synthetic instruction steps are recorded");
    CHECK(cpu.eip == RET_TOP && cpu.esp == STACK_TOP,
          "top-level caller owns and consumes the final return address");
    CHECK(cpu.eax == 0x76543210u && cpu.ebx == 0xb16b00b5u,
          "register changes survive normal nested return");
    CHECK(load_u32(STACK_TOP - 8u) == ARG_NESTED,
          "nested argument remains at its guest stack location");
    return 0;
}

static int test_unresolved_and_import_stops(const GuestImport *imports) {
    CPU cpu;
    GuestExecutionResult result;
    config = make_config(32, 8, imports, 1);
    after_stop = 0;

    prepare_cpu(&cpu);
    cpu.eax = 0x10203040u;
    CHECK(run_expect(&config, &cpu, IP_UNRESOLVED, GUEST_STOP_UNRESOLVED,
                     &result) == 0,
          "static unresolved target yields an explicit stop");
    CHECK(result.target == 0x00500000u && result.calls == 2,
          "unresolved stop identifies target and counts attempted call");
    CHECK(result.ip == IP_UNRESOLVED && cpu.eip == IP_UNRESOLVED,
          "call stop preserves current instruction context");
    CHECK(cpu.esp == STACK_TOP - 8u && load_u32(cpu.esp) == RET_NESTED,
          "unresolved call does not pop or clean its synthetic return");
    CHECK(cpu.ebx == 0x0badc0deu && cpu.eax == 0x10203040u && after_stop == 0,
          "register changes before stop remain and post-call code is skipped");
    CHECK(result.cpu.esp == cpu.esp && result.cpu.ebx == cpu.ebx,
          "stop result snapshots the preserved CPU state");

    prepare_cpu(&cpu);
    after_stop = 0;
    import_target = load_u32(imports[0].iat);
    CHECK(import_target == GUEST_IMPORT_BASE,
          "bound IAT points at the first import tag");
    CHECK(run_expect(&config, &cpu, IP_IMPORT, GUEST_STOP_IMPORT, &result) == 0,
          "bound import yields an explicit import stop");
    CHECK(result.target == import_target && result.import_index == 0,
          "import stop preserves tag and stable import index");
    CHECK(cpu.esp == STACK_TOP - 8u && load_u32(cpu.esp) == RET_NESTED &&
          after_stop == 0,
          "import stop leaves stack cleanup to the interrupted guest path");

    prepare_cpu(&cpu);
    CHECK(run_expect(&config, &cpu, IP_UNKNOWN_IMPORT, GUEST_STOP_UNRESOLVED,
                     &result) == 0,
          "unknown import tag is unresolved, not a host import");
    CHECK(result.target == GUEST_IMPORT_BASE + 7u && result.import_index == 0,
          "unknown tag is not falsely classified as a known import");
    CHECK(cpu.esp == STACK_TOP - 8u && after_stop == 0,
          "unknown import does not consume the caller frame");
    return 0;
}

static int test_import_binding_transaction(void) {
    GuestPEImage image = {
        .image_base = IMAGE_BASE,
        .image_size = IMAGE_SIZE,
        .entry_point = TEXT_BASE,
        .resource_address = 0,
        .resource_size = 0,
        .section_count = 1
    };
    GuestImport valid[] = {
        { IMAGE_BASE + 0x20u, "kernel32.dll", "CreateFileA" },
        { IMAGE_BASE + 0x24u, "user32.dll", "MessageBoxA" }
    };
    GuestImport overlap[] = {
        { IMAGE_BASE + 0x40u, "a.dll", "A" },
        { IMAGE_BASE + 0x42u, "b.dll", "B" }
    };
    GuestImport invalid_late[] = {
        { IMAGE_BASE + 0x60u, "a.dll", "A" },
        { IMAGE_BASE + 0x4000u, "b.dll", "B" }
    };
    GuestImport null_name[] = { { IMAGE_BASE + 0x80u, "a.dll", NULL } };
    static GuestImport too_many[4097];

    store_u32(valid[0].iat, 0xaaaaaaaa);
    store_u32(valid[1].iat, 0xbbbbbbbb);
    CHECK(guest_execution_bind_imports(&image, valid, 2) == 0,
          "valid imports bind after all slots pass validation");
    CHECK(load_u32(valid[0].iat) == GUEST_IMPORT_BASE &&
          load_u32(valid[1].iat) == GUEST_IMPORT_BASE + 1u,
          "bound IAT slots map to stable contiguous import tags");

    store_u32(overlap[0].iat, 0xcccccccc);
    CHECK(guest_execution_bind_imports(&image, overlap, 2) == EEXIST,
          "partially overlapping IAT slots are rejected");
    CHECK(load_u32(overlap[0].iat) == 0xcccccccc,
          "overlap validation fails before mutating earlier slots");

    store_u32(invalid_late[0].iat, 0xdddddddd);
    CHECK(guest_execution_bind_imports(&image, invalid_late, 2) == EINVAL,
          "uncommitted later IAT slot is rejected");
    CHECK(load_u32(invalid_late[0].iat) == 0xdddddddd,
          "uncommitted later slot leaves earlier candidate unchanged");
    CHECK(guest_execution_bind_imports(&image, null_name, 1) == EINVAL,
          "missing import name is rejected");
    CHECK(guest_memory_commit(IMAGE_BASE + GUEST_MEMORY_GRANULE,
                              IMAGE_SIZE - GUEST_MEMORY_GRANULE) == 0,
          "remaining synthetic image pages commit for import-count limit test");
    for (uint32_t i = 0; i < (uint32_t)(sizeof too_many / sizeof too_many[0]); ++i) {
        too_many[i] = (GuestImport){ IMAGE_BASE + 0x100u + i * 4u,
                                     "synthetic.dll", "SyntheticCall" };
    }
    CHECK(guest_execution_bind_imports(&image, too_many,
                                       (uint32_t)(sizeof too_many /
                                                  sizeof too_many[0])) == EINVAL,
          "oversized but otherwise valid import table is rejected");
    CHECK(guest_execution_bind_imports(&image, NULL, 1) == EINVAL,
          "missing import table is rejected");
    return 0;
}

static int test_instruction_memory_depth_and_budget(void) {
    CPU cpu;
    GuestExecutionResult result;
    GuestImport import = { IMAGE_BASE + 0x20u, "a.dll", "A" };

    config = make_config(32, 8, &import, 1);
    prepare_cpu(&cpu);
    after_stop = 0;
    CHECK(run_expect(&config, &cpu, IP_UNSUPPORTED, GUEST_STOP_INSTRUCTION,
                     &result) == 0,
          "unsupported operation has an explicit instruction stop");
    CHECK(result.ip == IP_UNSUPPORTED && result.target == IP_UNSUPPORTED &&
          cpu.eip == IP_UNSUPPORTED && after_stop == 0,
          "unsupported operation preserves fault address and skips following code");
    CHECK(cpu.esp == STACK_TOP - 4u && load_u32(cpu.esp) == RET_TOP,
          "unsupported operation performs no implicit return cleanup");

    prepare_cpu(&cpu);
    after_stop = 0;
    CHECK(run_expect(&config, &cpu, IP_MEMORY, GUEST_STOP_MEMORY, &result) == 0,
          "checked pointer rejects a cross-granule uncommitted access");
    CHECK(result.target == CROSS_BASE + GUEST_MEMORY_GRANULE - 2u &&
          cpu.eax == 0x11223344u && cpu.eip == IP_MEMORY && after_stop == 0,
          "memory stop preserves target, registers, and current instruction");
    CHECK(cpu.esp == STACK_TOP - 4u && load_u32(cpu.esp) == RET_TOP,
          "memory stop leaves stack intact");

    config.instruction_budget = 2;
    prepare_cpu(&cpu);
    cpu.eax = 10;
    CHECK(run_expect(&config, &cpu, IP_BUDGET, GUEST_STOP_BUDGET, &result) == 0,
          "instruction budget stops before the over-budget instruction executes");
    CHECK(result.instructions == 2 && result.ip == IP_BUDGET + 2u &&
          cpu.eip == IP_BUDGET + 2u && cpu.eax == 12,
          "budget stop records attempted IP and preserves prior instruction effects");
    CHECK(cpu.esp == STACK_TOP - 4u && load_u32(cpu.esp) == RET_TOP,
          "budget stop does not synthesize a return");

    config.instruction_budget = 32;
    config.depth_limit = 2;
    prepare_cpu(&cpu);
    after_stop = 0;
    depth_c_ran = 0;
    CHECK(run_expect(&config, &cpu, IP_DEPTH_A, GUEST_STOP_DEPTH, &result) == 0,
          "configured native-call depth limit stops before entering excess target");
    CHECK(result.target == IP_DEPTH_C && result.calls == 3 &&
          result.maximum_depth == 2 && depth_c_ran == 0,
          "depth stop reports attempted target while preserving maximum entered depth");
    CHECK(cpu.eax == 0xa001u && cpu.ebx == 0xb002u && after_stop == 0,
          "depth stop preserves earlier callee register effects and skips later code");
    CHECK(cpu.esp == STACK_TOP - 12u && load_u32(cpu.esp) == 0xca11b002u &&
          load_u32(STACK_TOP - 8u) == 0xca11a001u &&
          load_u32(STACK_TOP - 4u) == RET_TOP,
          "depth stop leaves all nested and top-level return words in place");
    return 0;
}

static int test_repeated_runs_and_reentrancy(void) {
    CPU cpu;
    GuestExecutionResult result;

    config = make_config(32, 8, NULL, 0);
    prepare_cpu(&cpu);
    CHECK(run_expect(&config, &cpu, IP_UNRESOLVED, GUEST_STOP_UNRESOLVED,
                     &result) == 0,
          "first run stops unresolved");
    prepare_cpu(&cpu);
    CHECK(run_expect(&config, &cpu, IP_SIMPLE, GUEST_STOP_RETURN, &result) == 0,
          "later run succeeds after a longjmp stop");
    CHECK(result.target == 0 && result.import_index == 0 &&
          result.instructions == 1 && result.calls == 1 &&
          result.maximum_depth == 1,
          "later result has no stale stop target or counters");
    CHECK(cpu.eax == 0x55aa55aau && cpu.eip == RET_TOP &&
          cpu.esp == STACK_TOP,
          "later run executes with clean top-level stack and CPU state");

    nested_result = (GuestExecutionResult){ .stop = GUEST_STOP_TIMEOUT,
                                            .target = UINT32_MAX };
    nested_run_rc = 0;
    prepare_cpu(&cpu);
    CHECK(run_expect(&config, &cpu, IP_BUSY, GUEST_STOP_RETURN, &result) == 0,
          "outer run returns after rejecting reentrant execution");
    CHECK(nested_run_rc == EBUSY && nested_result.stop == 0 &&
          nested_result.target == 0,
          "nested run is rejected and initializes its result without changing active run");
    CHECK(cpu.eip == RET_TOP && cpu.esp == STACK_TOP,
          "outer run remains intact after reentrant attempt");
    return 0;
}

static int test_bootstrap_validation_and_reset(void) {
    GuestPEImage image = {
        .image_base = IMAGE_BASE,
        .image_size = 0x3000u,
        .entry_point = IMAGE_BASE + 0x100u,
        .resource_address = 0,
        .resource_size = 0,
        .section_count = 1
    };
    CPU cpu;
    GuestPEImage invalid = image;

    memset(&cpu, 0x5a, sizeof cpu);
    CHECK(guest_bootstrap_init(NULL, &image) == EINVAL,
          "bootstrap rejects null CPU");
    CHECK(guest_bootstrap_init(&cpu, NULL) == EINVAL,
          "bootstrap rejects null image descriptor");
    CHECK(cpu.eax == UINT32_C(0x5a5a5a5a),
          "null-argument validation leaves CPU untouched");

    invalid.image_size = 0;
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects an empty image range");
    invalid = image;
    invalid.entry_point = image.image_base + image.image_size;
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects an entry at the exclusive image end");
    invalid = image;
    invalid.image_base = 0x00900000u;
    invalid.entry_point = invalid.image_base + 0x100u;
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects an image without committed backing");
    invalid.image_base = UINT32_MAX;
    invalid.image_size = 4u;
    invalid.entry_point = UINT32_MAX;
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects a guest image range that crosses 4 GiB");
    CHECK(cpu.eax == UINT32_C(0x5a5a5a5a),
          "invalid-image validation leaves CPU untouched");

    const uint32_t teb_collision = GUEST_TEB_BASE + 0x4000u;
    const uint32_t stack_collision = GUEST_STACK_LO + 0x4000u;
    CHECK(guest_memory_commit(teb_collision, GUEST_MEMORY_GRANULE) == 0,
          "synthetic colliding TEB image page commits");
    CHECK(guest_memory_commit(stack_collision, GUEST_MEMORY_GRANULE) == 0,
          "synthetic colliding stack image page commits");
    invalid = (GuestPEImage){
        .image_base = teb_collision, .image_size = 0x100u,
        .entry_point = teb_collision + 0x10u
    };
    store_u32(teb_collision, 0xdecafbad);
    memset(&cpu, 0x3c, sizeof cpu);
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects a committed image overlapping the TEB/PEB reservation");
    CHECK(load_u32(teb_collision) == 0xdecafbad &&
          cpu.eax == UINT32_C(0x3c3c3c3c),
          "TEB collision rejection preserves mapped image bytes and CPU");

    invalid.image_base = stack_collision;
    invalid.image_size = 0x100u;
    invalid.entry_point = stack_collision + 0x10u;
    store_u32(stack_collision, 0xfacefeed);
    CHECK(guest_bootstrap_init(&cpu, &invalid) == EINVAL,
          "bootstrap rejects a committed image overlapping the guest stack");
    CHECK(load_u32(stack_collision) == 0xfacefeed &&
          cpu.eax == UINT32_C(0x3c3c3c3c),
          "stack collision rejection preserves mapped image bytes and CPU");

    CHECK(guest_memory_commit(GUEST_TEB_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic TEB page commits for reset probe");
    CHECK(guest_memory_commit(GUEST_PEB_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic PEB page commits for reset probe");
    CHECK(guest_memory_commit(GUEST_STACK_LO, GUEST_MEMORY_GRANULE) == 0,
          "synthetic stack low page commits for reset probe");
    CHECK(guest_memory_commit(GUEST_STACK_HI - GUEST_MEMORY_GRANULE,
                              GUEST_MEMORY_GRANULE) == 0,
          "synthetic stack high page commits for reset probe");
    store_u32(GUEST_TEB_BASE + 0x100u, 0xaaaaaaaa);
    store_u32(GUEST_PEB_BASE + 0x100u, 0xbbbbbbbb);
    store_u32(GUEST_STACK_LO, 0xcccccccc);
    store_u32(GUEST_STACK_HI - 4u, 0xdddddddd);
    memset(&cpu, 0xa5, sizeof cpu);
    cpu.eax = 0xaaaaaaaa;
    cpu.esp = 0x12345678u;
    cpu.fs_base = 0x11111111u;
    cpu.gs_base = 0x22222222u;
    cpu.fcw = 0x2468u;
    cpu.st[0] = 3.25;
    cpu.xmm[0].u32[0] = 0xdeadbeefu;
    cpu.cf = cpu.zf = 1;

    CHECK(guest_bootstrap_init(&cpu, &image) == 0,
          "synthetic authenticated image bootstraps");
    CHECK(cpu.eip == image.entry_point && cpu.esp == GUEST_STACK_HI - 0x1000u,
          "bootstrap sets guest entry and reserved stack pointer");
    CHECK(cpu.fs_base == GUEST_TEB_BASE && cpu.gs_base == GUEST_TEB_BASE &&
          cpu.fcw == 0x037fu,
          "bootstrap sets x86 process bases and x87 control word");
    CHECK(cpu.eax == 0 && cpu.ecx == 0 && cpu.edx == 0 && cpu.ebx == 0 &&
          cpu.ebp == 0 && cpu.esi == 0 && cpu.edi == 0 && cpu.cf == 0 &&
          cpu.zf == 0 && cpu.st[0] == 0.0 && cpu.xmm[0].u32[0] == 0,
          "bootstrap clears prior registers, flags, x87, and SIMD state");
    CHECK(load_u32(GUEST_TEB_BASE + 0x00u) == UINT32_MAX &&
          load_u32(GUEST_TEB_BASE + 0x04u) == GUEST_STACK_HI &&
          load_u32(GUEST_TEB_BASE + 0x08u) == GUEST_STACK_LO &&
          load_u32(GUEST_TEB_BASE + 0x18u) == GUEST_TEB_BASE &&
          load_u32(GUEST_TEB_BASE + 0x20u) == 100u &&
          load_u32(GUEST_TEB_BASE + 0x24u) == 1u &&
          load_u32(GUEST_TEB_BASE + 0x2cu) == GUEST_TEB_BASE + 0x1000u &&
          load_u32(GUEST_TEB_BASE + 0x30u) == GUEST_PEB_BASE,
          "bootstrap writes the expected synthetic TEB fields");
    CHECK(load_u32(GUEST_PEB_BASE + 0x08u) == image.image_base &&
          load_u32(GUEST_PEB_BASE + 0xa4u) == 5u &&
          load_u32(GUEST_PEB_BASE + 0xa8u) == 1u,
          "bootstrap writes synthetic PEB image and version fields");
    CHECK(load_u32(GUEST_TEB_BASE + 0x100u) == 0 &&
          load_u32(GUEST_PEB_BASE + 0x100u) == 0 &&
          load_u32(GUEST_STACK_LO) == 0 &&
          load_u32(GUEST_STACK_HI - 4u) == 0,
          "bootstrap clears stale TEB, PEB, and both stack-boundary contents");

    store_u32(GUEST_TEB_BASE + 0x100u, 0x12345678u);
    store_u32(GUEST_PEB_BASE + 0x100u, 0x87654321u);
    store_u32(GUEST_STACK_LO, 0xaabbccddu);
    cpu.eax = 0xffffffffu;
    cpu.esp = 0;
    cpu.fs_base = 0;
    CHECK(guest_bootstrap_init(&cpu, &image) == 0,
          "a second bootstrap resets the same synthetic process layout");
    CHECK(cpu.eax == 0 && cpu.esp == GUEST_STACK_HI - 0x1000u &&
          cpu.fs_base == GUEST_TEB_BASE &&
          load_u32(GUEST_TEB_BASE + 0x100u) == 0 &&
          load_u32(GUEST_PEB_BASE + 0x100u) == 0 &&
          load_u32(GUEST_STACK_LO) == 0,
          "rebootstrap removes stale CPU and process-memory state");
    return 0;
}

int main(void) {
    GuestImport imports[] = {
        { IMAGE_BASE + 0x20u, "kernel32.dll", "CreateFileA" }
    };

    CHECK(guest_memory_init() == 0, "guest memory mapping initializes");
    CHECK(guest_memory_commit(STACK_BASE, STACK_TOP - STACK_BASE) == 0,
          "synthetic guest stack commits");
    CHECK(guest_memory_commit(IMAGE_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic image IAT page commits");
    CHECK(guest_memory_commit(CROSS_BASE, GUEST_MEMORY_GRANULE) == 0,
          "first cross-range granule commits");
    CHECK(guest_dispatch_init(&dispatch, TEXT_BASE, TEXT_SIZE,
                              function_addresses, guest_functions,
                              (uint32_t)(sizeof function_addresses /
                                         sizeof function_addresses[0])) == 0,
          "synthetic function dispatch table initializes");
    CHECK(guest_execution_bind_imports(
              &(GuestPEImage){ .image_base = IMAGE_BASE,
                               .image_size = IMAGE_SIZE,
                               .entry_point = IP_ROOT,
                               .section_count = 1 }, imports, 1) == 0,
          "synthetic import binds for execution-stop probe");

    CHECK(test_nested_call_and_stack_contract() == 0,
          "nested call contract tests pass");
    CHECK(test_import_binding_transaction() == 0,
          "import binding transaction tests pass");
    CHECK(test_unresolved_and_import_stops(imports) == 0,
          "unresolved and import stop tests pass");
    CHECK(test_instruction_memory_depth_and_budget() == 0,
          "instruction, memory, depth, and budget stop tests pass");
    CHECK(test_repeated_runs_and_reentrancy() == 0,
          "repeated and reentrant run tests pass");
    CHECK(test_bootstrap_validation_and_reset() == 0,
          "bootstrap validation and reset tests pass");

    guest_dispatch_destroy(&dispatch);
    CHECK(guest_memory_shutdown() == 0, "guest memory mapping shuts down");
    puts("PASS guest execution core");
    return 0;
}
