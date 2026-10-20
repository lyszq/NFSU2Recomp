#include "guest_bootstrap.h"
#include "guest_memory.h"
#include <errno.h>
#include <string.h>
int guest_bootstrap_init(CPU *cpu, const GuestPEImage *image) {
    if (!cpu || !image || !image->image_size ||
        !guest_memory_pointer(image->image_base, image->image_size, 1) ||
        image->entry_point < image->image_base ||
        (uint64_t)image->entry_point >= (uint64_t)image->image_base + image->image_size)
        return EINVAL;
    /* This is the existing NFSU2 process layout; reject colliding images. */
    uint64_t end = (uint64_t)image->image_base + image->image_size;
    if ((image->image_base < GUEST_TEB_BASE + 0x20000u && end > GUEST_TEB_BASE) ||
        (image->image_base < GUEST_STACK_HI && end > GUEST_STACK_LO)) return EINVAL;
    int rc = guest_memory_commit(GUEST_TEB_BASE, 0x20000u);
    if (rc) return rc;
    rc = guest_memory_commit(GUEST_STACK_LO, GUEST_STACK_HI - GUEST_STACK_LO);
    if (rc) return rc;
    memset(g_mem + GUEST_TEB_BASE, 0, 0x20000u);
    memset(g_mem + GUEST_STACK_LO, 0, GUEST_STACK_HI - GUEST_STACK_LO);
    MR32(GUEST_TEB_BASE + 0x00u) = 0xffffffffu;
    MR32(GUEST_TEB_BASE + 0x04u) = GUEST_STACK_HI;
    MR32(GUEST_TEB_BASE + 0x08u) = GUEST_STACK_LO;
    MR32(GUEST_TEB_BASE + 0x18u) = GUEST_TEB_BASE;
    MR32(GUEST_TEB_BASE + 0x20u) = 100u; /* Existing guest process identity. */
    MR32(GUEST_TEB_BASE + 0x24u) = 1u;
    MR32(GUEST_TEB_BASE + 0x2cu) = GUEST_TEB_BASE + 0x1000u;
    MR32(GUEST_TEB_BASE + 0x30u) = GUEST_PEB_BASE;
    MR32(GUEST_PEB_BASE + 0x08u) = image->image_base;
    MR32(GUEST_PEB_BASE + 0xa4u) = 5u;
    MR32(GUEST_PEB_BASE + 0xa8u) = 1u;
    memset(cpu, 0, sizeof *cpu);
    cpu->esp = GUEST_STACK_HI - 0x1000u;
    cpu->eip = image->entry_point;
    cpu->fcw = 0x037fu;
    cpu->fs_base = GUEST_TEB_BASE;
    cpu->gs_base = GUEST_TEB_BASE;
    return 0;
}
