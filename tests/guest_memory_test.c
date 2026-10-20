#include "guest_memory.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
        return 1; \
    } \
} while (0)

static int expect_fault(uint32_t address, int write_access, const char *label) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "FAIL fork for %s: errno=%d\n", label, errno);
        return 1;
    }
    if (pid == 0) {
        const struct rlimit no_core = { 0, 0 };
        (void)setrlimit(RLIMIT_CORE, &no_core);
        volatile uint8_t *p = (volatile uint8_t *)(g_mem + address);
        if (write_access) *p = 0x5au;
        else (void)*p;
        _exit(0);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid) {
        fprintf(stderr, "FAIL waitpid for %s: errno=%d\n", label, errno);
        return 1;
    }
    if (!WIFSIGNALED(status) ||
        (WTERMSIG(status) != SIGSEGV && WTERMSIG(status) != SIGBUS)) {
        fprintf(stderr, "FAIL %s: expected SIGSEGV/SIGBUS, status=0x%x\n",
                label, status);
        return 1;
    }
    return 0;
}

struct CommitWorker {
    uint32_t address;
    int rc;
};

static void *commit_worker(void *opaque) {
    struct CommitWorker *worker = (struct CommitWorker *)opaque;
    for (unsigned i = 0; i < 64; ++i) {
        worker->rc = guest_memory_commit(worker->address,
                                         GUEST_MEMORY_GRANULE);
        if (worker->rc) break;
    }
    return NULL;
}

static int test_bounds_zero_and_overlap(void) {
    const uint32_t base = 0x00004000u;
    const uint64_t granule = GUEST_MEMORY_GRANULE;

    CHECK(guest_memory_committed() == 0, "fresh mapping has no committed granules");
    CHECK(guest_memory_commit(0x00001234u, 0) == 0, "zero-length commit succeeds");
    CHECK(guest_memory_protect(0x00001234u, 0, GUEST_MEMORY_READ) == 0,
          "zero-length protection succeeds");
    CHECK(guest_memory_protect(0x00001234u, 0,
                               (enum GuestMemoryProtection)99) == EINVAL,
          "invalid protection is rejected even for an empty range");
    CHECK(guest_memory_pointer(0x00001234u, 0, 0) == NULL,
          "zero-length checked pointer is rejected");
    CHECK(guest_memory_committed() == 0, "zero-length requests change no metadata");

    CHECK(guest_memory_commit(UINT32_MAX, 2) == EOVERFLOW,
          "commit crossing 4 GiB is rejected");
    CHECK(guest_memory_pointer(UINT32_MAX, 2, 0) == NULL,
          "checked pointer crossing 4 GiB is rejected");
    CHECK(guest_memory_commit(UINT32_MAX, 0) == 0,
          "zero length at the final guest address does not wrap");
    CHECK(guest_memory_committed() == 0, "overflow and zero length commit nothing");

    CHECK(guest_memory_protect(base, granule, GUEST_MEMORY_READ) == EFAULT,
          "protection of unallocated guest RAM fails");
    CHECK(guest_memory_commit(base, granule) == 0,
          "first aligned granule commit succeeds");
    CHECK(guest_memory_committed() == granule, "first commit counts one granule");
    CHECK(guest_memory_commit(base + (uint32_t)granule, 2 * granule) == 0,
          "adjacent granules commit");
    CHECK(guest_memory_committed() == 3 * granule,
          "adjacent commit counts each new granule once");
    CHECK(guest_memory_commit(base, 3 * granule) == 0,
          "overlapping commit succeeds");
    CHECK(guest_memory_committed() == 3 * granule,
          "overlapping commit does not double-count granules");
    CHECK((g_cbits[0] & 0x0eu) == 0x0eu,
          "readability bitmap marks exactly the three committed pages");

    return 0;
}

static int test_aliasing_and_protection(void) {
    const uint32_t a_addr = 0x00004010u;
    const uint32_t b_addr = 0x00008000u;
    const uint32_t uncommitted_addr = 0x30000000u;
    uint8_t *a = (uint8_t *)guest_memory_pointer(a_addr, 16, 1);
    uint8_t *a_overlap = (uint8_t *)guest_memory_pointer(a_addr + 3, 5, 1);
    uint8_t *b = (uint8_t *)guest_memory_pointer(b_addr, 8, 1);
    uint8_t *cross_page = (uint8_t *)guest_memory_pointer(0x00007ff8u, 16, 1);
    const uint8_t source[8] = { 0x11u, 0x22u, 0x33u, 0x44u,
                                0x55u, 0x66u, 0x77u, 0x88u };
    uint8_t observed[8] = { 0 };

    CHECK(a != NULL && a_overlap != NULL && b != NULL && cross_page != NULL,
          "checked pointers translate committed writable ranges");
    CHECK(a_overlap == a + 3, "overlapping guest ranges alias at the same offset");
    CHECK(b == g_mem + b_addr && a == g_mem + a_addr,
          "guest addresses retain the linear g_mem offset mapping");
    CHECK(b - a == (ptrdiff_t)(b_addr - a_addr),
          "different guest addresses do not alias each other");
    CHECK(cross_page == g_mem + 0x00007ff8u,
          "one checked range can cross two committed granules");
    memcpy(a, source, sizeof source);
    memcpy(observed, a_overlap, sizeof observed - 3);
    CHECK(memcmp(observed, source + 3, sizeof observed - 3) == 0,
          "writes through one range are visible through an overlapping range");

    CHECK(expect_fault(uncommitted_addr, 1, "write to uncommitted guest page") == 0,
          "uncommitted page is protected by the host mapping");

    CHECK(guest_memory_protect(0x00004000u, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_READ) == 0,
          "RW granule can be changed to read-only");
    CHECK(guest_memory_pointer(a_addr, 1, 0) != NULL,
          "read-only range remains readable through checked pointer");
    CHECK(guest_memory_pointer(a_addr, 1, 1) == NULL,
          "read-only range rejects a checked write pointer");
    CHECK((g_cbits[0] & 0x02u) != 0,
          "read-only granule remains marked readable for legacy checks");
    CHECK(expect_fault(0x00004000u, 1, "write to read-only guest page") == 0,
          "read-only mapping rejects a real host write");

    CHECK(guest_memory_protect(0x00004000u, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_NONE) == 0,
          "committed granule can be made inaccessible");
    CHECK(guest_memory_pointer(a_addr, 1, 0) == NULL &&
          guest_memory_pointer(a_addr, 1, 1) == NULL,
          "inaccessible range rejects checked read and write pointers");
    CHECK(guest_memory_pointer(0x00007ff8u, 16, 0) == NULL,
          "cross-page checked access rejects a range with one inaccessible granule");
    CHECK((g_cbits[0] & 0x02u) == 0,
          "legacy readability bitmap clears when access is removed");
    CHECK(guest_memory_committed() == 3u * GUEST_MEMORY_GRANULE,
          "protection changes do not discard backing or decrement accounting");
    CHECK(expect_fault(0x00004000u, 0, "read from inaccessible guest page") == 0,
          "PROT_NONE mapping rejects a real host read");

    CHECK(guest_memory_protect(0x00004000u, GUEST_MEMORY_GRANULE,
                               GUEST_MEMORY_READ) == 0,
          "inaccessible allocated granule can be restored read-only");
    CHECK(guest_memory_pointer(a_addr, 1, 0) != NULL,
          "restored read access is reflected by checked pointer");
    CHECK(guest_memory_pointer(0x00007ff8u, 16, 0) != NULL,
          "cross-page checked access succeeds after restoring both pages");
    CHECK(guest_memory_pointer(a_addr, 1, 1) == NULL,
          "restored read-only access still rejects writes");
    const uint8_t *restored = (const uint8_t *)guest_memory_pointer(
        a_addr, sizeof source, 0);
    CHECK(restored != NULL, "restored data range is readable");
    memcpy(observed, restored, sizeof source);
    CHECK(memcmp(observed, source, sizeof source) == 0,
          "protection changes preserve guest bytes");

    CHECK(guest_memory_commit(0x00004000u, GUEST_MEMORY_GRANULE) == 0,
          "recommit restores read-write access");
    CHECK(guest_memory_pointer(a_addr, sizeof source, 1) != NULL,
          "recommitted range accepts a checked write pointer");
    CHECK(guest_memory_committed() == 3u * GUEST_MEMORY_GRANULE,
          "recommit preserves unique backing accounting");
    return 0;
}

static int test_concurrent_commits(void) {
    enum { WORKERS = 8 };
    const uint32_t base = 0x20000000u; /* aligned to one eight-bit bitmap byte */
    const uint64_t before = guest_memory_committed();
    pthread_t threads[WORKERS];
    struct CommitWorker workers[WORKERS];
    unsigned created = 0;

    for (unsigned i = 0; i < WORKERS; ++i) {
        workers[i].address = base + i * GUEST_MEMORY_GRANULE;
        workers[i].rc = 0;
        int rc = pthread_create(&threads[i], NULL, commit_worker, &workers[i]);
        if (rc) {
            fprintf(stderr, "FAIL pthread_create: errno=%d\n", rc);
            break;
        }
        ++created;
    }
    for (unsigned i = 0; i < created; ++i) {
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            fprintf(stderr, "FAIL pthread_join: errno=%d\n", rc);
            return 1;
        }
        CHECK(workers[i].rc == 0, "concurrent repeated commit succeeds");
    }
    CHECK(created == WORKERS, "all concurrent commit workers started");
    CHECK(guest_memory_committed() == before +
          (uint64_t)WORKERS * GUEST_MEMORY_GRANULE,
          "concurrent commits count each granule exactly once");
    CHECK(g_cbits[(base >> 14) >> 3] == 0xffu,
          "concurrent commits preserve all bits in one shared bitmap byte");
    CHECK(g_cbits[((base >> 14) + WORKERS) >> 3] == 0,
          "concurrent commits do not mark the following bitmap byte");
    return 0;
}

static int test_upper_boundary(void) {
    const uint64_t before = guest_memory_committed();
    uint8_t *last;

    CHECK(guest_memory_commit(UINT32_MAX, 1) == 0,
          "final byte of the 32-bit guest address space can be committed");
    last = (uint8_t *)guest_memory_pointer(UINT32_MAX, 1, 1);
    CHECK(last == g_mem + UINT32_MAX,
          "final guest byte maps to the final byte of the reservation");
    *last = 0xA7u;
    CHECK(*last == 0xA7u, "final guest byte is readable and writable");
    CHECK(guest_memory_committed() == before + GUEST_MEMORY_GRANULE,
          "top-boundary commit counts its final granule once");
    CHECK(guest_memory_commit(UINT32_MAX, 2) == EOVERFLOW,
          "top-boundary range does not wrap to guest address zero");
    CHECK(guest_memory_pointer(UINT32_MAX - 1u, 3, 0) == NULL,
          "checked pointer does not wrap through guest address zero");
    return 0;
}

static int test_all_bitmap_positions(void) {
    const uint32_t page_count = (uint32_t)(GUEST_MEMORY_SIZE /
                                           GUEST_MEMORY_GRANULE);
    CHECK(page_count == GUEST_MEMORY_BITMAP_SIZE * 8u,
          "bitmap covers the complete 4 GiB guest address space");
    CHECK(guest_memory_commit(0, GUEST_MEMORY_SIZE) == 0,
          "entire guest address space can be committed as one range");
    CHECK(guest_memory_committed() == GUEST_MEMORY_SIZE,
          "full-range commit accounts for every granule exactly once");

    for (unsigned i = 0; i < GUEST_MEMORY_BITMAP_SIZE; ++i) {
        CHECK(g_cbits[i] == 0xffu,
              "all eight readable bitmap positions are set in every byte");
    }
    for (uint32_t page = 0; page < page_count; ++page) {
        const uint32_t address = page * GUEST_MEMORY_GRANULE +
                                 (GUEST_MEMORY_GRANULE - 1u);
        void *p = guest_memory_pointer(address, 1, 0);
        CHECK(p == g_mem + address,
              "checked translation works at every bitmap position");
    }
    return 0;
}

static int test_lifecycle(void) {
    CHECK(guest_memory_shutdown() == 0, "mapping shuts down cleanly");
    CHECK(g_mem == NULL, "shutdown clears the exported guest base");
    CHECK(guest_memory_committed() == 0, "shutdown clears unique-byte accounting");
    CHECK(guest_memory_host_page_size() == 0, "shutdown clears host page metadata");
    for (unsigned i = 0; i < GUEST_MEMORY_BITMAP_SIZE; ++i) {
        CHECK(g_cbits[i] == 0, "shutdown clears all legacy readability bits");
    }
    CHECK(guest_memory_pointer(0, 1, 0) == NULL,
          "checked translation fails after shutdown");
    CHECK(guest_memory_commit(0, 1) == ENXIO,
          "nonempty commit requires an initialized mapping");
    CHECK(guest_memory_shutdown() == 0, "shutdown is idempotent");

    CHECK(guest_memory_init() == 0, "mapping can be initialized again");
    CHECK(guest_memory_commit(0x1234u, 1) == 0,
          "reinitialized mapping can commit guest RAM");
    CHECK(guest_memory_committed() == GUEST_MEMORY_GRANULE,
          "reinitialized metadata starts clean");
    CHECK(guest_memory_shutdown() == 0, "reinitialized mapping shuts down");
    return 0;
}

int main(void) {
    CHECK(sizeof(size_t) >= 8, "test requires a 64-bit host");
    CHECK(guest_memory_init() == 0, "4 GiB guest mapping initializes");
    const size_t page_size = guest_memory_host_page_size();
    CHECK(page_size != 0 && page_size <= GUEST_MEMORY_GRANULE &&
          GUEST_MEMORY_GRANULE % page_size == 0,
          "host page size is supported by the 16 KiB guest granule");

    CHECK(test_bounds_zero_and_overlap() == 0, "bounds/overlap tests pass");
    CHECK(test_aliasing_and_protection() == 0, "alias/protection tests pass");
    CHECK(test_concurrent_commits() == 0, "concurrent commit tests pass");
    CHECK(test_upper_boundary() == 0, "upper-boundary tests pass");
    CHECK(test_all_bitmap_positions() == 0, "bitmap coverage tests pass");
    CHECK(test_lifecycle() == 0, "lifecycle tests pass");

    puts("PASS guest memory core");
    return 0;
}
