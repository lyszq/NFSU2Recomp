/* The macOS offset mapping and bitmap policy, shared with iOS and POSIX tests.
 * Desktop fault diagnostics/watchpoints remain in mem.c. */
#include "guest_memory.h"
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

uint8_t *g_mem;
uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];
static uint8_t allocated[GUEST_MEMORY_BITMAP_SIZE];
static uint8_t writable[GUEST_MEMORY_BITMAP_SIZE];
static uint64_t committed;
static size_t host_page_size;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int bounds(uint32_t address, uint64_t size, uint64_t *lo, uint64_t *hi) {
    if (size > GUEST_MEMORY_SIZE - address) return EOVERFLOW;
    *lo = (uint64_t)address & ~(uint64_t)(GUEST_MEMORY_GRANULE - 1u);
    *hi = size ? ((uint64_t)address + size + GUEST_MEMORY_GRANULE - 1u) &
                 ~(uint64_t)(GUEST_MEMORY_GRANULE - 1u) : *lo;
    return 0;
}

int guest_memory_init(void) {
    int rc = 0;
    pthread_mutex_lock(&mutex);
    if (g_mem) goto done;
    const long ps = sysconf(_SC_PAGESIZE);
    if (sizeof(size_t) < 8 || ps <= 0 ||
        (ps & (ps - 1)) || (unsigned long)ps > GUEST_MEMORY_GRANULE ||
        GUEST_MEMORY_GRANULE % (unsigned long)ps) {
        rc = ENOTSUP;
        goto done;
    }
    /* PROT_NONE reserves address space, not 4 GiB of physical memory.
     * GUEST_MEMORY_RESERVE adds a trailing guard granule past 4 GiB so multi-byte
     * reads at 0xFFFFFFFF safely fault instead of spilling into adjacent memory. */
    void *region = mmap(NULL, (size_t)GUEST_MEMORY_RESERVE, PROT_NONE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region == MAP_FAILED) { rc = errno; goto done; }
    g_mem = region;
    host_page_size = (size_t)ps;
done:
    pthread_mutex_unlock(&mutex);
    return rc;
}

static int change(uint32_t address, uint64_t size,
                  enum GuestMemoryProtection protection, int commit) {
    uint64_t lo, hi;
    int rc = bounds(address, size, &lo, &hi);
    if (rc) return rc;
    if (protection < GUEST_MEMORY_NONE || protection > GUEST_MEMORY_READ_WRITE)
        return EINVAL;
    if (!size) return 0;
    uint64_t change_lo = lo;
    pthread_mutex_lock(&mutex);
    if (!g_mem) { rc = ENXIO; goto done; }
    /* ReadFile and other callers may recommit ranges that are already live.
     * Keep commit idempotent without repeating mprotect or rewriting the
     * page maps when every covered granule is already allocated, readable,
     * and writable. Read-only and inaccessible ranges still take the normal
     * path below so commit restores their write access. */
    if (commit && protection == GUEST_MEMORY_READ_WRITE) {
        int already_writable = 1;
        for (uint64_t a = lo; a < hi; a += GUEST_MEMORY_GRANULE) {
            unsigned pg = (unsigned)(a >> 14), i = pg >> 3;
            uint8_t bit = (uint8_t)(1u << (pg & 7));
            uint8_t readable = __atomic_load_n(&g_cbits[i], __ATOMIC_RELAXED);
            if (!(allocated[i] & bit) || !(readable & bit) ||
                !(writable[i] & bit)) {
                already_writable = 0;
                change_lo = a;
                break;
            }
        }
        if (already_writable) goto done;
    }
    if (!commit) {
        for (uint64_t a = lo; a < hi; a += GUEST_MEMORY_GRANULE) {
            unsigned pg = (unsigned)(a >> 14);
            if (!(allocated[pg >> 3] & (1u << (pg & 7)))) {
                rc = EFAULT;
                goto done;
            }
        }
    }
    int prot = protection == GUEST_MEMORY_NONE ? PROT_NONE : PROT_READ;
    if (protection == GUEST_MEMORY_READ_WRITE) prot |= PROT_WRITE;
    /* A commit can overlap a large already-RW prefix (for example, the
     * monotonic COM resource allocator's 1 MiB write cushion). The scan above
     * proves that prefix is fully RW while holding mutex, so changing only
     * the suffix preserves the requested final permissions and avoids
     * repeating mprotect and bitmap writes for pages that cannot change. */
    if (mprotect(g_mem + change_lo, (size_t)(hi - change_lo), prot)) {
        rc = errno;
        goto done;
    }
    for (uint64_t a = change_lo; a < hi; a += GUEST_MEMORY_GRANULE) {
        unsigned pg = (unsigned)(a >> 14), i = pg >> 3;
        uint8_t bit = (uint8_t)(1u << (pg & 7));
        if (!(allocated[i] & bit)) committed += GUEST_MEMORY_GRANULE;
        allocated[i] |= bit;
        uint8_t old = __atomic_load_n(&g_cbits[i], __ATOMIC_RELAXED);
        __atomic_store_n(&g_cbits[i], (uint8_t)((old & ~bit) |
                         (protection != GUEST_MEMORY_NONE ? bit : 0)), __ATOMIC_RELEASE);
        writable[i] = (uint8_t)((writable[i] & ~bit) |
                              (protection == GUEST_MEMORY_READ_WRITE ? bit : 0));
    }
done:
    pthread_mutex_unlock(&mutex);
    return rc;
}

int guest_memory_commit(uint32_t address, uint64_t size) {
    return change(address, size, GUEST_MEMORY_READ_WRITE, 1);
}
int guest_memory_protect(uint32_t address, uint64_t size,
                         enum GuestMemoryProtection protection) {
    return change(address, size, protection, 0);
}
void *guest_memory_pointer(uint32_t address, uint64_t size, int write_access) {
    uint64_t lo, hi;
    if (!size || bounds(address, size, &lo, &hi)) return NULL;
    pthread_mutex_lock(&mutex);
    void *result = NULL;
    if (!g_mem) goto done;
    const uint8_t *bits = write_access ? writable : g_cbits;
    for (uint64_t a = lo; a < hi; a += GUEST_MEMORY_GRANULE) {
        unsigned pg = (unsigned)(a >> 14);
        if (!(bits[pg >> 3] & (1u << (pg & 7)))) goto done;
    }
    result = g_mem + address;
done:
    pthread_mutex_unlock(&mutex);
    return result;
}
uint64_t guest_memory_committed(void) {
    pthread_mutex_lock(&mutex);
    uint64_t result = committed;
    pthread_mutex_unlock(&mutex);
    return result;
}
size_t guest_memory_host_page_size(void) {
    pthread_mutex_lock(&mutex);
    size_t result = host_page_size;
    pthread_mutex_unlock(&mutex);
    return result;
}
int guest_memory_shutdown(void) {
    int rc = 0;
    pthread_mutex_lock(&mutex);
    if (g_mem && munmap(g_mem, (size_t)GUEST_MEMORY_RESERVE)) { rc = errno; goto done; }
    g_mem = NULL;
    host_page_size = 0;
    committed = 0;
    memset(g_cbits, 0, sizeof g_cbits);
    memset(allocated, 0, sizeof allocated);
    memset(writable, 0, sizeof writable);
done:
    pthread_mutex_unlock(&mutex);
    return rc;
}
