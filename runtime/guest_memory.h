/* Shared x86-32 guest VM. No game data, signals, UI, or executable mappings. */
#ifndef NFSU2_GUEST_MEMORY_H
#define NFSU2_GUEST_MEMORY_H
#include <stddef.h>
#include <stdint.h>

#define GUEST_MEMORY_SIZE UINT64_C(0x100000000)
#define GUEST_MEMORY_GRANULE 0x4000u
#define GUEST_MEMORY_BITMAP_SIZE (1u << 15)

/* These symbols preserve cpu.h's generated-code ABI and 16 KiB readability bitmap. */
extern uint8_t *g_mem;
extern uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];

enum GuestMemoryProtection {
    GUEST_MEMORY_NONE = 0,
    GUEST_MEMORY_READ = 1,
    GUEST_MEMORY_READ_WRITE = 2
};

/* Return 0 on success, otherwise an errno value; never exit the application.
 * Ranges use 64-bit lengths, reject overflow past 4 GiB, and never wrap.
 * Zero length is a no-op. Protection rounds out to 16 KiB guest granules.
 * Protect only accepts already committed granules; NONE removes access but
 * does not discard contents. Recommit restores RW access without zeroing.
 * No request can grant host execute permission (static ARM64 code is separate).
 * Metadata operations are serialized; callers must quiesce guest execution
 * before protect/shutdown. Raw cpu.h access still requires valid committed RAM.
 */
int guest_memory_init(void);
int guest_memory_commit(uint32_t address, uint64_t size);
int guest_memory_protect(uint32_t address, uint64_t size,
                         enum GuestMemoryProtection protection);
int guest_memory_shutdown(void);
uint64_t guest_memory_committed(void); /* unique committed bytes, not RSS */
size_t guest_memory_host_page_size(void);
/* Checked translation for loaders/host bridges. NULL for inaccessible ranges.
 * Unlike guest integer arithmetic, a multibyte access never wraps at 4 GiB.
 */
void *guest_memory_pointer(uint32_t address, uint64_t size, int write_access);
#endif
