#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cpu.h"
#include "guest_memory.h"
#include "guest_process.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

static void write_u32(uint32_t addr, uint32_t val) {
    void *ptr = guest_memory_pointer(addr, 4, 1);
    if (ptr) {
        memcpy(ptr, &val, sizeof(val));
    }
}

static uint32_t read_u32(uint32_t addr) {
    uint32_t val = 0;
    void *ptr = guest_memory_pointer(addr, 4, 0);
    if (ptr) {
        memcpy(&val, ptr, sizeof(val));
    }
    return val;
}

static void init_test_cpu(CPU *cpu, uint32_t esp, uint32_t eip) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = esp;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = eip;
    cpu->fs_base = 0x00200000u;
    cpu->gs_base = 0x00300000u;
    eflags_set(cpu, 0x202u);
}

static int check_preserved_regs(const CPU *before, const CPU *after) {
    if (before->ecx != after->ecx) return 0;
    if (before->edx != after->edx) return 0;
    if (before->ebx != after->ebx) return 0;
    if (before->ebp != after->ebp) return 0;
    if (before->esi != after->esi) return 0;
    if (before->edi != after->edi) return 0;
    if (before->fs_base != after->fs_base) return 0;
    if (before->gs_base != after->gs_base) return 0;
    if (eflags_get((CPU *)before) != eflags_get((CPU *)after)) return 0;
    return 1;
}

static int test_init_validation(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;

    /* Invalid arguments */
    CHECK(guest_process_init(NULL, &img) != 0);
    CHECK(guest_process_init(&proc, NULL) != 0);

    /* Nonempty check: image_size == 0 */
    img.image_size = 0;
    CHECK(guest_process_init(&proc, &img) != 0);

    /* uint64 image_end > 4 GiB */
    img.image_base = 0xFFFFF000u;
    img.image_size = 0x2000u;
    CHECK(guest_process_init(&proc, &img) != 0);

    /* Reservation overlap checks with full 64 KiB reservation [c20000, c30000) */
    img.image_base = GUEST_PROCESS_BASE;
    img.image_size = GUEST_PROCESS_RESERVED;
    CHECK(guest_process_init(&proc, &img) != 0);

    img.image_base = GUEST_PROCESS_BASE + 0x4000u;
    img.image_size = 0x4000u;
    CHECK(guest_process_init(&proc, &img) != 0);

    img.image_base = GUEST_PROCESS_BASE - 0x4000u;
    img.image_size = 0x8000u;
    CHECK(guest_process_init(&proc, &img) != 0);

    img.image_base = GUEST_PROCESS_BASE + 0x8000u;
    img.image_size = 0x10000u;
    CHECK(guest_process_init(&proc, &img) != 0);

    img.image_base = GUEST_PROCESS_BASE - 0x10000u;
    img.image_size = 0x30000u;
    CHECK(guest_process_init(&proc, &img) != 0);

    /* Accessible foreign reservation rejected BEFORE mutation */
    CHECK(guest_memory_commit(GUEST_PROCESS_BASE + 0x4000u, 0x4000u) == 0);
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) != 0);
    CHECK(proc.initialized == 0);

    /* Reset VM to clear committed granule */
    guest_memory_shutdown();
    CHECK(guest_memory_init() == 0);

    /* Uninitialized g_mem rejects init */
    guest_memory_shutdown();
    CHECK(guest_process_init(&proc, &img) != 0);
    CHECK(guest_memory_init() == 0);

    return 0;
}

static int test_init_contents_and_cleanup(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;

    CHECK(guest_process_init(&proc, &img) == 0);
    CHECK(proc.initialized == 1);
    CHECK(proc.environment_a_refs == 0);
    CHECK(proc.environment_w_refs == 0);

    /* Reject duplicate init */
    CHECK(guest_process_init(&proc, &img) != 0);

    /* Verify canonical ASCII command line including NUL */
    const char *cmd = (const char *)guest_memory_pointer(GUEST_PROCESS_COMMAND, sizeof(GUEST_PROCESS_COMMAND_LINE), 0);
    CHECK(cmd != NULL);
    CHECK(strcmp(cmd, GUEST_PROCESS_COMMAND_LINE) == 0);

    /* Distinct narrow empty env block: 2 NUL bytes */
    const uint8_t *env_a = (const uint8_t *)guest_memory_pointer(GUEST_PROCESS_ENV_A, 2, 0);
    CHECK(env_a != NULL);
    CHECK(env_a[0] == 0 && env_a[1] == 0);

    /* Distinct wide empty env block: 2 zero UTF-16 code units (4 bytes) */
    const uint8_t *env_w = (const uint8_t *)guest_memory_pointer(GUEST_PROCESS_ENV_W, 4, 0);
    CHECK(env_w != NULL);
    CHECK(env_w[0] == 0 && env_w[1] == 0 && env_w[2] == 0 && env_w[3] == 0);

    /* First 16 KiB committed, remainder of 64 KiB reservation uncommitted */
    CHECK(guest_memory_pointer(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES, 0) != NULL);
    CHECK(guest_memory_pointer(GUEST_PROCESS_BASE + GUEST_PROCESS_BYTES, 0x4000u, 0) == NULL);

    /* Cleanup zeroes metadata */
    guest_process_cleanup(&proc);
    CHECK(proc.initialized == 0);
    CHECK(proc.environment_a_refs == 0);
    CHECK(proc.environment_w_refs == 0);

    /* Shutdown-cleanup-reinit cycle */
    guest_memory_shutdown();
    guest_process_cleanup(&proc);
    CHECK(guest_memory_init() == 0);
    CHECK(guest_process_init(&proc, &img) == 0);
    CHECK(proc.initialized == 1);
    guest_process_cleanup(&proc);
    guest_memory_shutdown();
    CHECK(guest_memory_init() == 0);
    return 0;
}

static int test_unknown_and_uninit_import(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) == 0);

    CHECK(guest_memory_commit(0x00100000u, 0x10000u) == 0);

    CPU cpu;
    init_test_cpu(&cpu, 0x00108000u, 0x00401000u);
    GuestImport imp = { 0, "KERNEL32.dll", "GetCommandLineA" };
    uint32_t fault = 0xDEADBEEFu;

    /* Unknown / malformed host inputs return 0 without mutation */
    CHECK(guest_process_import(NULL, &imp, &proc, &fault) == 0);
    CHECK(guest_process_import(&cpu, NULL, &proc, &fault) == 0);
    CHECK(guest_process_import(&cpu, &imp, NULL, &fault) == 0);
    CHECK(fault == 0xDEADBEEFu);

    /* Unknown library / function */
    GuestImport imp_unk_lib = { 0, "USER32.dll", "GetCommandLineA" };
    CHECK(guest_process_import(&cpu, &imp_unk_lib, &proc, &fault) == 0);
    CHECK(fault == 0xDEADBEEFu);

    GuestImport imp_unk_fn = { 0, "KERNEL32.dll", "ExitProcess" };
    CHECK(guest_process_import(&cpu, &imp_unk_fn, &proc, &fault) == 0);
    CHECK(fault == 0xDEADBEEFu);

    /* Known API on uninitialized state => -2, fault = PROCESS_BASE */
    GuestProcess uninit_proc;
    memset(&uninit_proc, 0, sizeof(uninit_proc));
    write_u32(0x00108000u, 0x00402000u);
    CPU before = cpu;
    int rc = guest_process_import(&cpu, &imp, &uninit_proc, &fault);
    CHECK(rc == -2);
    CHECK(fault == GUEST_PROCESS_BASE);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    return 0;
}

static int test_stdcall_getcommandline_cp(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) == 0);

    CHECK(guest_memory_commit(0x00100000u, 0x10000u) == 0);

    CPU cpu;
    init_test_cpu(&cpu, 0x00108000u, 0x00401000u);
    uint32_t fault = 0;

    /* GetCommandLineA: argc 0 */
    write_u32(0x00108000u, 0x00409999u);
    GuestImport imp = { 0, "kernel32.dll", "GetCommandLineA" };
    CPU before = cpu;
    int rc = guest_process_import(&cpu, &imp, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_COMMAND);
    CHECK(cpu.eip == 0x00409999u);
    CHECK(cpu.esp == 0x00108004u);
    CHECK(check_preserved_regs(&before, &cpu));

    /* GetACP: argc 0, EAX=1252 */
    write_u32(0x00108004u, 0x00408888u);
    imp.library = "kErNeL32.DLL";
    imp.name = "GetACP";
    before = cpu;
    rc = guest_process_import(&cpu, &imp, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1252);
    CHECK(cpu.eip == 0x00408888u);
    CHECK(cpu.esp == 0x00108008u);
    CHECK(check_preserved_regs(&before, &cpu));

    /* GetOEMCP: argc 0, EAX=437 */
    write_u32(0x00108008u, 0x00407777u);
    imp.name = "GetOEMCP";
    before = cpu;
    rc = guest_process_import(&cpu, &imp, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 437);
    CHECK(cpu.eip == 0x00407777u);
    CHECK(cpu.esp == 0x0010800Cu);
    CHECK(check_preserved_regs(&before, &cpu));

    return 0;
}

static int test_env_lifecycle_and_caps(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) == 0);

    CHECK(guest_memory_commit(0x00100000u, 0x10000u) == 0);
    CHECK(guest_memory_commit(0x00200000u, 0x10000u) == 0);

    CPU cpu;
    init_test_cpu(&cpu, 0x00108000u, 0x00401000u);
    cpu.fs_base = 0x00200000u;
    uint32_t fault = 0;

    GuestImport imp_get_a = { 0, "KERNEL32.dll", "GetEnvironmentStrings" };
    GuestImport imp_get_w = { 0, "KERNEL32.dll", "GetEnvironmentStringsW" };
    GuestImport imp_free_a = { 0, "KERNEL32.dll", "FreeEnvironmentStringsA" };
    GuestImport imp_free_w = { 0, "KERNEL32.dll", "FreeEnvironmentStringsW" };

    /* Single get A and get W */
    write_u32(0x00108000u, 0x00402222u);
    int rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_ENV_A);
    CHECK(proc.environment_a_refs == 1);
    CHECK(proc.environment_w_refs == 0);

    write_u32(0x00108000u, 0x00403333u);
    cpu.esp = 0x00108000u;
    rc = guest_process_import(&cpu, &imp_get_w, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_ENV_W);
    CHECK(proc.environment_a_refs == 1);
    CHECK(proc.environment_w_refs == 1);

    /* Wrong encoding free => -2 */
    write_u32(0x00108000u, 0x00404444u);
    write_u32(0x00108004u, GUEST_PROCESS_ENV_W);
    cpu.esp = 0x00108000u;
    CPU before = cpu;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == -2);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);
    CHECK(proc.environment_a_refs == 1);
    CHECK(proc.environment_w_refs == 1);

    /* Balanced free A */
    write_u32(0x00108004u, GUEST_PROCESS_ENV_A);
    before = cpu;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(cpu.eip == 0x00404444u);
    CHECK(cpu.esp == 0x00108008u);
    CHECK(check_preserved_regs(&before, &cpu));
    CHECK(proc.environment_a_refs == 0);

    /* Double free A => -2 */
    write_u32(0x00108000u, 0x00405555u);
    write_u32(0x00108004u, GUEST_PROCESS_ENV_A);
    cpu.esp = 0x00108000u;
    before = cpu;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == -2);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);
    CHECK(proc.environment_a_refs == 0);

    /* Balanced free W */
    write_u32(0x00108004u, GUEST_PROCESS_ENV_W);
    rc = guest_process_import(&cpu, &imp_free_w, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(proc.environment_w_refs == 0);

    /* Double free W => -2 */
    cpu.esp = 0x00108000u;
    before = cpu;
    rc = guest_process_import(&cpu, &imp_free_w, &proc, &fault);
    CHECK(rc == -2);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);
    CHECK(proc.environment_w_refs == 0);

    /* Independent 32 lease cap on A */
    for (uint32_t i = 0; i < GUEST_PROCESS_ENV_LEASES; i++) {
        write_u32(0x00108000u, 0x00406000u + i);
        cpu.esp = 0x00108000u;
        rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
        CHECK(rc == 1);
        CHECK(cpu.eax == GUEST_PROCESS_ENV_A);
        CHECK(proc.environment_a_refs == i + 1);
    }
    CHECK(proc.environment_a_refs == 32);
    CHECK(proc.environment_w_refs == 0);

    /* 33rd get with fs_base == 0 => -2 */
    cpu.fs_base = 0;
    write_u32(0x00108000u, 0x00407000u);
    cpu.esp = 0x00108000u;
    before = cpu;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == -2);
    CHECK(proc.environment_a_refs == 32);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    /* 33rd get with valid TEB preflight => NULL result, LastError=8 */
    cpu.fs_base = 0x00200000u;
    write_u32(0x00200034u, 0x11223344u);
    write_u32(0x00200000u + 34u, 0x11223344u);
    write_u32(0x00108000u, 0x00407100u);
    cpu.esp = 0x00108000u;
    before = cpu;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0);
    CHECK(cpu.eip == 0x00407100u);
    CHECK(cpu.esp == 0x00108004u);
    CHECK(check_preserved_regs(&before, &cpu));
    CHECK(read_u32(0x00200034u) == 8 || read_u32(0x00200000u + 34u) == 8);
    CHECK(proc.environment_a_refs == 32);

    /* Normal success preserves LastError */
    write_u32(0x00108000u, 0x00407200u);
    write_u32(0x00108004u, GUEST_PROCESS_ENV_A);
    cpu.esp = 0x00108000u;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(proc.environment_a_refs == 31);

    write_u32(0x00200034u, 0x55667788u);
    write_u32(0x00200000u + 34u, 0x55667788u);
    write_u32(0x00108000u, 0x00407300u);
    cpu.esp = 0x00108000u;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_ENV_A);
    CHECK(proc.environment_a_refs == 32);
    CHECK(read_u32(0x00200034u) == 0x55667788u || read_u32(0x00200000u + 34u) == 0x55667788u);

    /* Independent 32 lease cap on W */
    for (uint32_t i = 0; i < GUEST_PROCESS_ENV_LEASES; i++) {
        write_u32(0x00108000u, 0x00408000u + i);
        cpu.esp = 0x00108000u;
        rc = guest_process_import(&cpu, &imp_get_w, &proc, &fault);
        CHECK(rc == 1);
        CHECK(cpu.eax == GUEST_PROCESS_ENV_W);
        CHECK(proc.environment_w_refs == i + 1);
    }
    CHECK(proc.environment_w_refs == 32);

    /* Cap error on W with valid TEB */
    write_u32(0x00200034u, 0);
    write_u32(0x00200000u + 34u, 0);
    write_u32(0x00108000u, 0x00408100u);
    cpu.esp = 0x00108000u;
    rc = guest_process_import(&cpu, &imp_get_w, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0);
    CHECK(read_u32(0x00200034u) == 8 || read_u32(0x00200000u + 34u) == 8);
    CHECK(proc.environment_w_refs == 32);

    /* Free all 32 leases on both */
    for (uint32_t i = 0; i < GUEST_PROCESS_ENV_LEASES; i++) {
        write_u32(0x00108000u, 0x00409000u);
        write_u32(0x00108004u, GUEST_PROCESS_ENV_A);
        cpu.esp = 0x00108000u;
        rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
        CHECK(rc == 1);

        write_u32(0x00108000u, 0x00409000u);
        write_u32(0x00108004u, GUEST_PROCESS_ENV_W);
        cpu.esp = 0x00108000u;
        rc = guest_process_import(&cpu, &imp_free_w, &proc, &fault);
        CHECK(rc == 1);
    }
    CHECK(proc.environment_a_refs == 0);
    CHECK(proc.environment_w_refs == 0);

    return 0;
}

static int test_memory_protection_and_faults(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) == 0);

    CHECK(guest_memory_commit(0x00100000u, 0x10000u) == 0);

    CPU cpu;
    init_test_cpu(&cpu, 0x00108000u, 0x00401000u);
    GuestImport imp_cmd = { 0, "KERNEL32.dll", "GetCommandLineA" };
    GuestImport imp_get_a = { 0, "KERNEL32.dll", "GetEnvironmentStrings" };
    uint32_t fault = 0;

    /* GUEST_MEMORY_READ works */
    CHECK(guest_memory_protect(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES, GUEST_MEMORY_READ) == 0);

    write_u32(0x00108000u, 0x00401111u);
    int rc = guest_process_import(&cpu, &imp_cmd, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_COMMAND);

    write_u32(0x00108004u, 0x00402222u);
    cpu.esp = 0x00108004u;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == GUEST_PROCESS_ENV_A);
    CHECK(proc.environment_a_refs == 1);

    /* GUEST_MEMORY_NONE causes -1 fault, leaves CPU and lease count intact */
    CHECK(guest_memory_protect(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES, GUEST_MEMORY_NONE) == 0);

    write_u32(0x00108000u, 0x00403333u);
    cpu.esp = 0x00108000u;
    CPU before = cpu;
    fault = 0;
    rc = guest_process_import(&cpu, &imp_cmd, &proc, &fault);
    CHECK(rc == -1);
    CHECK(fault == GUEST_PROCESS_COMMAND);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    fault = 0;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == -1);
    CHECK(proc.environment_a_refs == 1);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    /* Restore RW */
    CHECK(guest_memory_protect(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES, GUEST_MEMORY_READ_WRITE) == 0);

    GuestImport imp_free_a = { 0, "KERNEL32.dll", "FreeEnvironmentStringsA" };
    write_u32(0x00108000u, 0x00404444u);
    write_u32(0x00108004u, GUEST_PROCESS_ENV_A);
    cpu.esp = 0x00108000u;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == 1);
    CHECK(proc.environment_a_refs == 0);

    return 0;
}

static int test_bad_frames_and_overflow_teb(void) {
    GuestProcess proc;
    memset(&proc, 0, sizeof(proc));
    GuestPEImage img;
    memset(&img, 0, sizeof(img));
    img.image_base = 0x00400000u;
    img.image_size = 0x00100000u;
    CHECK(guest_process_init(&proc, &img) == 0);

    CHECK(guest_memory_commit(0x00100000u, 0x10000u) == 0);

    CPU cpu;
    init_test_cpu(&cpu, 0x00108000u, 0x00401000u);
    GuestImport imp_cmd = { 0, "KERNEL32.dll", "GetCommandLineA" };
    GuestImport imp_free_a = { 0, "KERNEL32.dll", "FreeEnvironmentStringsA" };
    GuestImport imp_get_a = { 0, "KERNEL32.dll", "GetEnvironmentStrings" };
    uint32_t fault = 0;

    /* Bad unmapped stack pointer => -1, CPU intact */
    cpu.esp = 0x90000000u;
    CPU before = cpu;
    int rc = guest_process_import(&cpu, &imp_cmd, &proc, &fault);
    CHECK(rc == -1);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    /* Wrapped stack frame at top of 4 GiB => -1, CPU intact */
    cpu.esp = 0xFFFFFFFCu;
    before = cpu;
    rc = guest_process_import(&cpu, &imp_free_a, &proc, &fault);
    CHECK(rc == -1);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);

    /* TEB offset overflow on cap error: uint64(fs) + 34 > 4 GiB */
    proc.environment_a_refs = GUEST_PROCESS_ENV_LEASES;
    cpu.esp = 0x00108000u;
    write_u32(0x00108000u, 0x00401111u);
    cpu.fs_base = 0xFFFFFFE0u;
    before = cpu;
    fault = 0;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0xFFFFFFFFu);
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);
    CHECK(proc.environment_a_refs == 32);

    /* TEB unwritable on cap error => -1 */
    cpu.fs_base = 0x30000000u;
    before = cpu;
    fault = 0;
    rc = guest_process_import(&cpu, &imp_get_a, &proc, &fault);
    CHECK(rc == -1);
    CHECK(fault == 0x30000034u || fault == (0x30000000u + 34u));
    CHECK(memcmp(&cpu, &before, sizeof(CPU)) == 0);
    CHECK(proc.environment_a_refs == 32);

    return 0;
}

int main(void) {
    if (guest_memory_init() != 0) {
        fprintf(stderr, "guest_memory_init failed\n");
        return 1;
    }

    if (test_init_validation() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_init_contents_and_cleanup() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_unknown_and_uninit_import() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_stdcall_getcommandline_cp() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_env_lifecycle_and_caps() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_memory_protection_and_faults() != 0) return 1;
    guest_memory_shutdown(); if (guest_memory_init() != 0) return 1;
    if (test_bad_frames_and_overflow_teb() != 0) return 1;

    guest_memory_shutdown();
    printf("PASS | guest process contracts\n");
    return 0;
}
