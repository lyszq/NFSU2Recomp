/* Desktop adapter links the shared core; no game image or generated C needed. */
#include "../runtime/cpu.h"
#include "../runtime/guest_memory.h"
#include <stdio.h>
extern uint64_t mem_committed(void);
int main(void) {
    mem_init();
    mem_init();
    mem_commit(0x400001u, 1);
    mem_commit(0x400002u, 1);
    mem_commit(0x800001u, 0);
    if (!mem_is_committed(0x400001u) || mem_is_committed(0x800001u) ||
        mem_committed() != GUEST_MEMORY_GRANULE) return 1;
    MR32(0x400004u) = 0x12345678u;
    if (MR32(0x400004u) != 0x12345678u) return 1;
    mem_commit(0xfffffffcu, 16); /* Legacy desktop API clips at 4 GiB. */
    MR32(0xfffffffcu) = 0xabcdef01u;
    if (MR32(0xfffffffcu) != 0xabcdef01u ||
        mem_committed() != 2u * GUEST_MEMORY_GRANULE) return 1;
    if (guest_memory_shutdown()) return 1;
    puts("PASS | desktop mem_init/mem_commit/MR32 adapter uses shared core");
    return 0;
}
