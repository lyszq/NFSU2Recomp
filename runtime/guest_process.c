#include "guest_process.h"
#include "guest_memory.h"
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

int guest_process_init(GuestProcess *proc, const GuestPEImage *image)
{
    if (!proc || !image || !g_mem) {
        return EINVAL;
    }
    if (proc->initialized) {
        return EBUSY;
    }
    if (image->image_size == 0) {
        return EINVAL;
    }

    uint64_t img_base = (uint64_t)image->image_base;
    uint64_t img_size = (uint64_t)image->image_size;
    uint64_t img_end = img_base + img_size;
    if (img_end > GUEST_MEMORY_SIZE) {
        return EINVAL;
    }

    uint64_t res_start = (uint64_t)GUEST_PROCESS_BASE;
    uint64_t res_end = res_start + (uint64_t)GUEST_PROCESS_RESERVED;
    if (img_base < res_end && res_start < img_end) {
        return EINVAL;
    }

    for (uint32_t addr = GUEST_PROCESS_BASE;
         addr < GUEST_PROCESS_BASE + GUEST_PROCESS_RESERVED;
         addr += GUEST_MEMORY_GRANULE) {
        if (guest_memory_pointer(addr, 1, 0) != NULL) {
            return EBUSY;
        }
    }

    int rc = guest_memory_commit(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES);
    if (rc != 0) {
        return rc;
    }

    void *ptr = guest_memory_pointer(GUEST_PROCESS_BASE, GUEST_PROCESS_BYTES, 1);
    if (!ptr) {
        return ENOMEM;
    }

    memset(ptr, 0, GUEST_PROCESS_BYTES);
    memcpy((uint8_t *)ptr + (GUEST_PROCESS_COMMAND - GUEST_PROCESS_BASE),
           GUEST_PROCESS_COMMAND_LINE,
           sizeof(GUEST_PROCESS_COMMAND_LINE));

    proc->environment_a_refs = 0;
    proc->environment_w_refs = 0;
    proc->initialized = 1;
    return 0;
}

void guest_process_cleanup(GuestProcess *proc)
{
    if (proc) {
        proc->initialized = 0;
        proc->environment_a_refs = 0;
        proc->environment_w_refs = 0;
    }
}

static int handle_env_getter(CPU *cpu, GuestProcess *proc, uint32_t ret_ip,
                             int is_wide, uint32_t *fault)
{
    uint32_t env_addr = is_wide ? GUEST_PROCESS_ENV_W : GUEST_PROCESS_ENV_A;
    uint64_t check_size = is_wide ? 4ULL : 2ULL;

    if (!guest_memory_pointer(env_addr, check_size, 0)) {
        *fault = env_addr;
        return -1;
    }

    uint32_t *refs = is_wide ? &proc->environment_w_refs : &proc->environment_a_refs;

    if (*refs >= GUEST_PROCESS_ENV_LEASES) {
        if (cpu->fs_base == 0) {
            *fault = 0;
            return -2;
        }

        uint64_t teb_addr = (uint64_t)cpu->fs_base + 0x34ULL;
        if (teb_addr > 0xFFFFFFFFULL) {
            *fault = 0xFFFFFFFFu;
            return -1;
        }
        if (teb_addr + 4ULL > 0x100000000ULL) {
            *fault = (uint32_t)teb_addr;
            return -1;
        }

        void *teb_ptr = guest_memory_pointer((uint32_t)teb_addr, 4ULL, 1);
        if (!teb_ptr) {
            *fault = (uint32_t)teb_addr;
            return -1;
        }

        uint32_t last_error = 8;
        memcpy(teb_ptr, &last_error, 4);

        cpu->eax = 0;
        cpu->eip = ret_ip;
        cpu->esp += 4;
        return 1;
    }

    (*refs)++;
    cpu->eax = env_addr;
    cpu->eip = ret_ip;
    cpu->esp += 4;
    return 1;
}

static int handle_env_free(CPU *cpu, GuestProcess *proc, uint32_t ret_ip,
                           uint32_t arg_ptr, int is_wide, uint32_t *fault)
{
    uint32_t expected_addr = is_wide ? GUEST_PROCESS_ENV_W : GUEST_PROCESS_ENV_A;
    uint32_t *refs = is_wide ? &proc->environment_w_refs : &proc->environment_a_refs;

    if (arg_ptr != expected_addr || *refs == 0) {
        *fault = arg_ptr;
        return -2;
    }

    (*refs)--;
    cpu->eax = 1;
    cpu->eip = ret_ip;
    cpu->esp += 8;
    return 1;
}

int guest_process_import(CPU *cpu, const GuestImport *imp,
                         GuestProcess *proc, uint32_t *fault)
{
    if (!cpu || !imp || !proc || !fault) {
        return 0;
    }
    if (!imp->library || !imp->name) {
        return 0;
    }
    if (strcasecmp(imp->library, "KERNEL32.dll") != 0) {
        return 0;
    }

    int is_cmd = (strcmp(imp->name, "GetCommandLineA") == 0);
    int is_env_a = (strcmp(imp->name, "GetEnvironmentStrings") == 0);
    int is_env_w = (strcmp(imp->name, "GetEnvironmentStringsW") == 0);
    int is_free_a = (strcmp(imp->name, "FreeEnvironmentStringsA") == 0);
    int is_free_w = (strcmp(imp->name, "FreeEnvironmentStringsW") == 0);
    int is_acp = (strcmp(imp->name, "GetACP") == 0);
    int is_oemcp = (strcmp(imp->name, "GetOEMCP") == 0);

    if (!is_cmd && !is_env_a && !is_env_w && !is_free_a &&
        !is_free_w && !is_acp && !is_oemcp) {
        return 0;
    }

    if (!proc->initialized) {
        *fault = GUEST_PROCESS_BASE;
        return -2;
    }

    uint32_t argc = (is_free_a || is_free_w) ? 1u : 0u;
    uint64_t frame_bytes = (uint64_t)(argc + 1u) * 4ULL;

    if ((uint64_t)cpu->esp + frame_bytes > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    void *frame = guest_memory_pointer(cpu->esp, frame_bytes, 0);
    if (!frame) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_ip = 0;
    memcpy(&ret_ip, frame, 4);

    uint32_t arg1 = 0;
    if (argc >= 1u) {
        memcpy(&arg1, (const uint8_t *)frame + 4, 4);
    }

    if (is_cmd) {
        if (!guest_memory_pointer(GUEST_PROCESS_COMMAND,
                                  sizeof(GUEST_PROCESS_COMMAND_LINE), 0)) {
            *fault = GUEST_PROCESS_COMMAND;
            return -1;
        }
        cpu->eax = GUEST_PROCESS_COMMAND;
        cpu->eip = ret_ip;
        cpu->esp += 4;
        return 1;
    }

    if (is_env_a) {
        return handle_env_getter(cpu, proc, ret_ip, 0, fault);
    }

    if (is_env_w) {
        return handle_env_getter(cpu, proc, ret_ip, 1, fault);
    }

    if (is_free_a) {
        return handle_env_free(cpu, proc, ret_ip, arg1, 0, fault);
    }

    if (is_free_w) {
        return handle_env_free(cpu, proc, ret_ip, arg1, 1, fault);
    }

    if (is_acp) {
        cpu->eax = 1252;
        cpu->eip = ret_ip;
        cpu->esp += 4;
        return 1;
    }

    if (is_oemcp) {
        cpu->eax = 437;
        cpu->eip = ret_ip;
        cpu->esp += 4;
        return 1;
    }

    return 0;
}
