#include "guest_startup.h"
#include "guest_memory.h"
#include <stdint.h>
#include <string.h>
#include <strings.h>

int guest_startup_import(CPU *cpu, const GuestImport *import, uint32_t *fault) {
    if (cpu == NULL || import == NULL || import->library == NULL ||
        import->name == NULL || fault == NULL) {
        return 0;
    }

    if (strcasecmp(import->library, "kernel32.dll") != 0 ||
        strcmp(import->name, "GetStartupInfoA") != 0) {
        return 0;
    }

    const void *frame = guest_memory_pointer(cpu->esp, 8, 0);
    if (frame == NULL) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t ret_ip = 0;
    uint32_t lp_startup_info = 0;
    memcpy(&ret_ip, frame, sizeof(ret_ip));
    memcpy(&lp_startup_info, (const uint8_t *)frame + 4, sizeof(lp_startup_info));

    if (lp_startup_info == 0) {
        *fault = 0;
        return -1;
    }

    void *out = guest_memory_pointer(lp_startup_info, 68, 1);
    if (out == NULL) {
        *fault = lp_startup_info;
        return -1;
    }

    uint8_t buf[68];
    memset(buf, 0, sizeof(buf));
    buf[0] = 68;
    memcpy(out, buf, sizeof(buf));

    cpu->eip = ret_ip;
    cpu->esp = (uint32_t)(cpu->esp + 8U);

    return 1;
}
