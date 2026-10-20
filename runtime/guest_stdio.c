#include "guest_stdio.h"
#include "guest_memory.h"
#include <stdint.h>
#include <string.h>
#include <strings.h>

int guest_stdio_import(CPU *cpu, const GuestImport *imp, uint32_t *fault)
{
    if (!cpu || !imp || !fault || !imp->name || !imp->library) {
        return 0;
    }

    if (strcasecmp(imp->library, "kernel32.dll") != 0) {
        return 0;
    }

    const int is_get_std_handle = (strcmp(imp->name, "GetStdHandle") == 0);
    const int is_get_file_type = (strcmp(imp->name, "GetFileType") == 0);

    if (!is_get_std_handle && !is_get_file_type) {
        return 0;
    }

    const void *frame_ptr = guest_memory_pointer(cpu->esp, 8ULL, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint8_t frame[8];
    memcpy(frame, frame_ptr, sizeof(frame));

    uint32_t ret_addr;
    uint32_t arg;
    memcpy(&ret_addr, frame, sizeof(ret_addr));
    memcpy(&arg, frame + 4, sizeof(arg));

    if (is_get_std_handle) {
        if (arg != 0xFFFFFFF6U && arg != 0xFFFFFFF5U && arg != 0xFFFFFFF4U) {
            return 0;
        }

        cpu->eax = 0U;
        cpu->eip = ret_addr;
        cpu->esp += 8U;
        return 1;
    }

    /* GetFileType */
    if (arg != 0U && arg != 0xFFFFFFFFU) {
        return 0;
    }

    if (cpu->fs_base == 0U) {
        *fault = 0U;
        return -2;
    }

    const uint64_t teb_sum = (uint64_t)cpu->fs_base + 0x34ULL;
    if (teb_sum > (uint64_t)UINT32_MAX) {
        *fault = UINT32_MAX;
        return -1;
    }

    const uint32_t teb_addr = (uint32_t)teb_sum;
    void *teb_ptr = guest_memory_pointer(teb_addr, 4ULL, 1);
    if (!teb_ptr) {
        *fault = teb_addr;
        return -1;
    }

    const uint32_t last_error = 6U;
    memcpy(teb_ptr, &last_error, sizeof(last_error));

    cpu->eax = 0U;
    cpu->eip = ret_addr;
    cpu->esp += 8U;
    return 1;
}
