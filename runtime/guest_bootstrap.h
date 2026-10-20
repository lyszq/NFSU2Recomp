#ifndef NFSU2_GUEST_BOOTSTRAP_H
#define NFSU2_GUEST_BOOTSTRAP_H
#include "cpu.h"
#include "guest_pe.h"
#define GUEST_TEB_BASE 0x00c00000u
#define GUEST_PEB_BASE 0x00c10000u
#define GUEST_STACK_LO 0x7f000000u
#define GUEST_STACK_HI 0x7ff00000u
/* Shared process/CPU setup from tests/boot.c, on an authenticated loaded image.
 * Resets the guest stack/TEB/PEB, not the game image. Owner must quiesce guest
 * execution. No host APIs are claimed or implemented by these guest structures.
 * Commit failure may leave new guest pages allocated; the owner tears down
 * its mapping after a failed probe. CPU is initialized only after both commits.
 * Does not push a return sentinel; caller chooses entry/return convention.
 */
int guest_bootstrap_init(CPU *cpu, const GuestPEImage *image);
#endif
