#include "guest_error.h"
#include "guest_memory.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

int guest_error_import(CPU *cpu, const GuestImport *imp, uint32_t *fault)
{
    if (!cpu || !imp || !imp->library || !imp->name || !fault) {
        return 0;
    }

    if (strcasecmp(imp->library, "KERNEL32.dll") != 0) {
        return 0;
    }

    int is_set;
    uint32_t argc;

    if (strcmp(imp->name, "GetLastError") == 0) {
        is_set = 0;
        argc = 0;
    } else if (strcmp(imp->name, "SetLastError") == 0) {
        is_set = 1;
        argc = 1;
    } else {
        return 0;
    }

    uint32_t frame_bytes = (argc + 1U) * 4U;
    uint64_t esp_sum = (uint64_t)cpu->esp + (uint64_t)frame_bytes;
    if (esp_sum > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    void *frame_ptr = guest_memory_pointer(cpu->esp, (uint64_t)frame_bytes, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t frame[2];
    memcpy(frame, frame_ptr, (size_t)frame_bytes);

    if (cpu->fs_base == 0) {
        *fault = 0;
        return -2;
    }

    uint64_t teb_sum = (uint64_t)cpu->fs_base + 0x34ULL;
    if (teb_sum > 0xFFFFFFFFULL) {
        *fault = UINT32_MAX;
        return -1;
    }

    uint32_t teb_addr = (uint32_t)teb_sum;
    int is_write = is_set ? 1 : 0;
    void *teb_ptr = guest_memory_pointer(teb_addr, (uint64_t)sizeof(uint32_t), is_write);
    if (!teb_ptr) {
        *fault = teb_addr;
        return -1;
    }

    if (is_set) {
        uint32_t new_err = frame[1];
        memcpy(teb_ptr, &new_err, sizeof(uint32_t));
    } else {
        uint32_t cur_err = 0;
        memcpy(&cur_err, teb_ptr, sizeof(uint32_t));
        cpu->eax = cur_err;
    }

    cpu->eip = frame[0];
    cpu->esp += frame_bytes;

    return 1;
}
