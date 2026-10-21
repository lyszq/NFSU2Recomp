#include "cpu.h"
#include "guest_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int mem_load_pe(const char *path);
extern uint32_t g_image_base, g_image_size, g_image_entry;
extern uint32_t g_res_dir_va, g_res_dir_size;

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s (errno=%d)\n", \
                __FILE__, __LINE__, (message), errno); \
        result = 1; \
        goto cleanup; \
    } \
} while (0)

enum {
    DOS_NT_OFFSET = 0x80,
    OPTIONAL_SIZE = 0xe0,
    OPTIONAL_OFFSET = DOS_NT_OFFSET + 24,
    SECTION_TABLE = OPTIONAL_OFFSET + OPTIONAL_SIZE,
    SECTION_COUNT = 3,
    HEADER_SIZE = 0x400,
    FILE_SIZE = 0x800,
    TEXT_RVA = 0x1000,
    TEXT_VIRTUAL_SIZE = 0x1000,
    TEXT_RAW_OFFSET = 0x400,
    TEXT_RAW_SIZE = 0x200,
    DATA_RVA = 0x3000,
    DATA_SIZE = 0x100,
    DATA_RAW_OFFSET = 0x600,
    BSS_RVA = 0x5000,
    BSS_SIZE = 0x100,
    ENTRY_RVA = 0x1010,
    RESOURCE_RVA = DATA_RVA,
    RESOURCE_SIZE = 0x20
};

#define IMAGE_BASE UINT32_C(0x00400000)
#define IMAGE_SIZE UINT32_C(0x00008000)

struct PEFixture {
    uint8_t bytes[FILE_SIZE];
};

static void put16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void set_section(struct PEFixture *fixture, unsigned index,
                        const char *name, uint32_t virtual_size,
                        uint32_t virtual_address, uint32_t raw_size,
                        uint32_t raw_offset, uint32_t characteristics) {
    uint8_t *section = fixture->bytes + SECTION_TABLE + index * 40u;
    memcpy(section, name, strlen(name));
    put32(section + 8, virtual_size);
    put32(section + 12, virtual_address);
    put32(section + 16, raw_size);
    put32(section + 20, raw_offset);
    put32(section + 36, characteristics);
}

static void make_fixture(struct PEFixture *fixture) {
    uint8_t *nt, *coff, *optional;
    memset(fixture, 0, sizeof *fixture);
    put16(fixture->bytes, 0x5a4d);
    put32(fixture->bytes + 0x3c, DOS_NT_OFFSET);

    nt = fixture->bytes + DOS_NT_OFFSET;
    put32(nt, 0x00004550u);
    coff = nt + 4;
    put16(coff, 0x014cu);            /* IMAGE_FILE_MACHINE_I386 */
    put16(coff + 2, SECTION_COUNT);
    put16(coff + 16, OPTIONAL_SIZE);

    optional = fixture->bytes + OPTIONAL_OFFSET;
    put16(optional, 0x010bu);        /* PE32 optional-header magic */
    put32(optional + 16, ENTRY_RVA);
    put32(optional + 28, IMAGE_BASE);
    put32(optional + 56, IMAGE_SIZE);
    put32(optional + 60, HEADER_SIZE);
    put32(optional + 92, 16u);       /* NumberOfRvaAndSizes */
    put32(optional + 112, RESOURCE_RVA);
    put32(optional + 116, RESOURCE_SIZE);

    set_section(fixture, 0, ".text", TEXT_VIRTUAL_SIZE, TEXT_RVA,
                TEXT_RAW_SIZE, TEXT_RAW_OFFSET, 0x60000020u);
    set_section(fixture, 1, ".data", DATA_SIZE, DATA_RVA,
                DATA_SIZE, DATA_RAW_OFFSET, 0xc0000040u);
    set_section(fixture, 2, ".bss", BSS_SIZE, BSS_RVA,
                0, 0, 0xc0000080u);

    for (unsigned i = 0; i < TEXT_RAW_SIZE; ++i)
        fixture->bytes[TEXT_RAW_OFFSET + i] = (uint8_t)(0xa5u + 13u * i);
    for (unsigned i = 0; i < DATA_SIZE; ++i)
        fixture->bytes[DATA_RAW_OFFSET + i] = (uint8_t)(0x31u ^ (7u * i));
}

static int write_fixture(const char *path, const struct PEFixture *fixture) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return -1;
    size_t offset = 0;
    while (offset < sizeof fixture->bytes) {
        ssize_t written = write(fd, fixture->bytes + offset,
                                sizeof fixture->bytes - offset);
        if (written <= 0) {
            int saved_errno = errno ? errno : EIO;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += (size_t)written;
    }
    return close(fd);
}

static int test_adapter(const char *path) {
    int result = 0;
    struct PEFixture fixture;
    uint8_t *active_mapping = NULL;
    uint64_t active_committed = 0;
    uint32_t active_globals[5];

    make_fixture(&fixture);
    fixture.bytes[0] = 0;            /* bad DOS magic */
    CHECK(write_fixture(path, &fixture) == 0, "write malformed synthetic PE");
    g_image_base = 0x11111111u;
    g_image_size = 0x22222222u;
    g_image_entry = 0x33333333u;
    g_res_dir_va = 0x44444444u;
    g_res_dir_size = 0x55555555u;
    errno = 0;
    CHECK(mem_load_pe(path) == -1 && errno == EINVAL,
          "malformed input is rejected with the loader errno");
    CHECK(g_mem == NULL && guest_memory_committed() == 0,
          "malformed input is rejected before a guest mapping is created");
    CHECK(g_image_base == 0x11111111u && g_image_size == 0x22222222u &&
          g_image_entry == 0x33333333u && g_res_dir_va == 0x44444444u &&
          g_res_dir_size == 0x55555555u,
          "malformed input does not publish partial legacy image globals");

    make_fixture(&fixture);
    CHECK(write_fixture(path, &fixture) == 0, "write valid synthetic PE");
    errno = 0;
    CHECK(mem_load_pe(path) == 0, "load valid PE through full-runtime adapter");
    CHECK(g_image_base == IMAGE_BASE && g_image_size == IMAGE_SIZE &&
          g_image_entry == IMAGE_BASE + ENTRY_RVA &&
          g_res_dir_va == IMAGE_BASE + RESOURCE_RVA &&
          g_res_dir_size == RESOURCE_SIZE,
          "successful load publishes legacy image and resource globals");
    CHECK(g_mem != NULL && guest_memory_committed() != 0,
          "successful adapter load owns a guest-memory mapping");
    CHECK(g_mem[IMAGE_BASE + TEXT_RVA] == 0xa5u &&
          g_mem[IMAGE_BASE + TEXT_RVA + TEXT_RAW_SIZE - 1u] ==
              (uint8_t)(0xa5u + 13u * (TEXT_RAW_SIZE - 1u)),
          "text section raw bytes are copied to the guest image");
    CHECK(g_mem[IMAGE_BASE + DATA_RVA] == 0x31u &&
          g_mem[IMAGE_BASE + DATA_RVA + DATA_SIZE - 1u] ==
              (uint8_t)(0x31u ^ (7u * (DATA_SIZE - 1u))),
          "data section raw bytes are copied to the guest image");
    CHECK(g_mem[IMAGE_BASE + BSS_RVA] == 0 &&
          g_mem[IMAGE_BASE + BSS_RVA + BSS_SIZE - 1u] == 0,
          "BSS remains zero-filled");

    active_mapping = g_mem;
    active_committed = guest_memory_committed();
    active_globals[0] = g_image_base;
    active_globals[1] = g_image_size;
    active_globals[2] = g_image_entry;
    active_globals[3] = g_res_dir_va;
    active_globals[4] = g_res_dir_size;
    errno = 0;
    CHECK(mem_load_pe(path) == -1 && errno == EBUSY,
          "a second load fails while the guest mapping is active");
    CHECK(g_mem == active_mapping && guest_memory_committed() == active_committed &&
          g_mem[IMAGE_BASE + TEXT_RVA] == 0xa5u,
          "busy load preserves the active mapping and its contents");
    CHECK(g_image_base == active_globals[0] && g_image_size == active_globals[1] &&
          g_image_entry == active_globals[2] && g_res_dir_va == active_globals[3] &&
          g_res_dir_size == active_globals[4],
          "busy load preserves the published legacy image globals");

cleanup:
    if (g_mem && guest_memory_shutdown() != 0) {
        fprintf(stderr, "FAIL %s:%d: guest mapping cleanup failed (errno=%d)\n",
                __FILE__, __LINE__, errno);
        result = 1;
    }
    return result;
}

int main(int argc, char **argv) {
    char path[] = "/tmp/nfsu2-full-pe-adapter-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: create synthetic PE fixture (errno=%d)\n", errno);
        return 1;
    }
    if (close(fd) != 0) {
        fprintf(stderr, "FAIL: close synthetic PE fixture (errno=%d)\n", errno);
        (void)unlink(path);
        return 1;
    }

    int result = test_adapter(path);
    if (unlink(path) != 0) {
        fprintf(stderr, "FAIL: remove synthetic PE fixture (errno=%d)\n", errno);
        result = 1;
    }
    if (!result) puts("PASS full PE adapter");
    if (!result && argc == 2) {
        /* Private CI has already authenticated this exact input's SHA-256. */
        if (mem_load_pe(argv[1]) || g_image_base != 0x00400000u ||
            g_image_size != 0x0052fc18u || g_image_entry != 0x0075bcc7u ||
            g_res_dir_va != 0x008bc000u || g_res_dir_size != 0x00038508u) {
            fprintf(stderr, "FAIL | actual private image adapter metadata (errno=%d)\n", errno);
            result = 1;
        } else {
            puts("PASS | authenticated actual image uses checked PE adapter; no guest execution");
        }
        if (guest_memory_shutdown()) result = 1;
    }
    return result;
}
