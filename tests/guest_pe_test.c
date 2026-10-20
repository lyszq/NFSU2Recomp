#include "guest_memory.h"
#include "guest_pe.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
        return 1; \
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
    TEXT_VIRTUAL_SIZE = 0x100,
    TEXT_RAW_OFFSET = 0x400,
    TEXT_RAW_SIZE = 0x200,
    DATA_RVA = 0x3000,
    DATA_VIRTUAL_SIZE = 0x80,
    DATA_RAW_OFFSET = 0x600,
    DATA_RAW_SIZE = 0x200,
    BSS_RVA = 0x5000,
    BSS_SIZE = 0x100,
    ENTRY_RVA = 0x1010,
    RESOURCE_RVA = 0x3000,
    RESOURCE_SIZE = 0x20
};

#define IMAGE_BASE UINT32_C(0x00400000)
#define IMAGE_SIZE UINT32_C(0x0052fc18) /* Deliberately not 16 KiB aligned. */

struct PEFixture {
    uint8_t bytes[FILE_SIZE];
    size_t length;
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

static uint8_t text_byte(unsigned i) {
    return (uint8_t)(0xa5u + 13u * i);
}

static uint8_t data_byte(unsigned i) {
    return (uint8_t)(0x31u ^ (7u * i));
}

static void set_section(struct PEFixture *fixture, unsigned index,
                        const char *name, uint32_t virtual_size,
                        uint32_t virtual_address, uint32_t raw_size,
                        uint32_t raw_offset, uint32_t characteristics) {
    uint8_t *s = fixture->bytes + SECTION_TABLE + index * 40u;
    (void)memcpy(s, name, strlen(name));
    put32(s + 8, virtual_size);
    put32(s + 12, virtual_address);
    put32(s + 16, raw_size);
    put32(s + 20, raw_offset);
    put32(s + 36, characteristics);
}

static void make_fixture(struct PEFixture *fixture) {
    uint8_t *nt, *coff, *opt;
    memset(fixture, 0, sizeof *fixture);
    fixture->length = sizeof fixture->bytes;
    put16(fixture->bytes, 0x5a4d);
    put32(fixture->bytes + 0x3c, DOS_NT_OFFSET);

    nt = fixture->bytes + DOS_NT_OFFSET;
    put32(nt, 0x00004550u);
    coff = nt + 4;
    put16(coff, 0x014cu);             /* IMAGE_FILE_MACHINE_I386 */
    put16(coff + 2, SECTION_COUNT);
    put16(coff + 16, OPTIONAL_SIZE);
    put16(coff + 18, 0x0102u);        /* executable image, 32-bit machine */

    opt = fixture->bytes + OPTIONAL_OFFSET;
    put16(opt, 0x010bu);              /* PE32 optional-header magic */
    put32(opt + 16, ENTRY_RVA);
    put32(opt + 20, TEXT_RVA);
    put32(opt + 24, DATA_RVA);
    put32(opt + 28, IMAGE_BASE);
    put32(opt + 32, 0x1000u);         /* SectionAlignment */
    put32(opt + 36, 0x200u);          /* FileAlignment */
    put32(opt + 56, IMAGE_SIZE);
    put32(opt + 60, HEADER_SIZE);
    put32(opt + 92, 16u);             /* NumberOfRvaAndSizes */
    put32(opt + 112, RESOURCE_RVA);   /* DataDirectory[2], resources */
    put32(opt + 116, RESOURCE_SIZE);

    set_section(fixture, 0, ".text", TEXT_VIRTUAL_SIZE, TEXT_RVA,
                TEXT_RAW_SIZE, TEXT_RAW_OFFSET, 0x60000020u);
    set_section(fixture, 1, ".data", DATA_VIRTUAL_SIZE, DATA_RVA,
                DATA_RAW_SIZE, DATA_RAW_OFFSET, 0xc0000040u);
    set_section(fixture, 2, ".bss", BSS_SIZE, BSS_RVA,
                0, 0, 0xc0000080u);

    for (unsigned i = 0; i < TEXT_RAW_SIZE; ++i)
        fixture->bytes[TEXT_RAW_OFFSET + i] = text_byte(i);
    for (unsigned i = 0; i < DATA_RAW_SIZE; ++i)
        fixture->bytes[DATA_RAW_OFFSET + i] = data_byte(i);
}

static int is_zero_image(const GuestPEImage *image) {
    GuestPEImage zero;
    memset(&zero, 0, sizeof zero);
    return memcmp(image, &zero, sizeof zero) == 0;
}

static int expect_rejected(const char *label, const struct PEFixture *fixture,
                           int expected_error) {
    GuestPEImage image;
    char diagnostic[128];
    int rc;

    if (g_mem != NULL) {
        fprintf(stderr, "FAIL %s: test started with active guest mapping\n", label);
        return 1;
    }
    memset(&image, 0xa5, sizeof image);
    memset(diagnostic, 0xa5, sizeof diagnostic);
    rc = guest_pe_load(fixture->bytes, fixture->length, &image,
                       diagnostic, sizeof diagnostic);
    if (rc != expected_error) {
        fprintf(stderr, "FAIL %s: expected error %d, got %d (%s)\n",
                label, expected_error, rc, diagnostic);
        return 1;
    }
    if (g_mem != NULL || guest_memory_committed() != 0) {
        fprintf(stderr, "FAIL %s: invalid input created guest memory\n", label);
        return 1;
    }
    if (!is_zero_image(&image)) {
        fprintf(stderr, "FAIL %s: error left a partial output image\n", label);
        return 1;
    }
    if (diagnostic[0] != 'F') {
        fprintf(stderr, "FAIL %s: error diagnostic was not populated\n", label);
        return 1;
    }
    return 0;
}

static int expect_truncated(const char *label, size_t length) {
    struct PEFixture fixture;
    make_fixture(&fixture);
    fixture.length = length;
    return expect_rejected(label, &fixture, EINVAL);
}

static int test_truncated_boundaries(void) {
    CHECK(expect_truncated("empty file", 0) == 0, "empty PE is rejected");
    CHECK(expect_truncated("short DOS header", 63) == 0,
          "truncated DOS header is rejected");
    CHECK(expect_truncated("missing NT header", 64) == 0,
          "complete DOS header without NT header is rejected");
    CHECK(expect_truncated("truncated PE signature", DOS_NT_OFFSET + 3u) == 0,
          "partial PE signature is rejected");
    CHECK(expect_truncated("short NT signature/COFF header", DOS_NT_OFFSET + 23u) == 0,
          "truncated NT/COFF header is rejected");
    CHECK(expect_truncated("missing optional header", OPTIONAL_OFFSET) == 0,
          "missing optional header is rejected");
    CHECK(expect_truncated("truncated optional header",
                           OPTIONAL_OFFSET + OPTIONAL_SIZE - 1u) == 0,
          "truncated optional header is rejected");
    CHECK(expect_truncated("truncated section table",
                           SECTION_TABLE + SECTION_COUNT * 40u - 1u) == 0,
          "truncated section table is rejected");
    CHECK(expect_truncated("truncated image headers", HEADER_SIZE - 1u) == 0,
          "truncated image headers are rejected");
    CHECK(expect_truncated("truncated section raw data", FILE_SIZE - 1u) == 0,
          "truncated section raw data is rejected");

    struct PEFixture fixture;
    make_fixture(&fixture);
    put32(fixture.bytes + 0x3c, UINT32_MAX - 15u);
    CHECK(expect_rejected("NT offset outside input", &fixture, EINVAL) == 0,
          "out-of-file NT offset is rejected");
    return 0;
}

static int test_malformed_headers(void) {
    struct PEFixture fixture;
    make_fixture(&fixture);
    fixture.bytes[0] = 0;
    CHECK(expect_rejected("bad DOS magic", &fixture, EINVAL) == 0,
          "invalid DOS magic is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + DOS_NT_OFFSET, 0);
    CHECK(expect_rejected("bad PE signature", &fixture, EINVAL) == 0,
          "invalid PE signature is rejected");

    make_fixture(&fixture);
    put16(fixture.bytes + DOS_NT_OFFSET + 4, 0x8664u);
    CHECK(expect_rejected("non-i386 machine", &fixture, EINVAL) == 0,
          "non-i386 PE is rejected");

    make_fixture(&fixture);
    put16(fixture.bytes + OPTIONAL_OFFSET, 0x020bu);
    CHECK(expect_rejected("PE32+ magic", &fixture, ENOTSUP) == 0,
          "PE32+ is rejected as unsupported");

    make_fixture(&fixture);
    put16(fixture.bytes + DOS_NT_OFFSET + 20, 95u);
    CHECK(expect_rejected("short optional-header declaration", &fixture, EINVAL) == 0,
          "optional-header size below PE32 minimum is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 60,
          SECTION_TABLE + SECTION_COUNT * 40u - 1u);
    CHECK(expect_rejected("section table exceeds SizeOfHeaders", &fixture, EINVAL) == 0,
          "section table outside declared headers is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 60, IMAGE_SIZE + 1u);
    CHECK(expect_rejected("headers exceed image", &fixture, EINVAL) == 0,
          "header size beyond image is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 92, 17u);
    CHECK(expect_rejected("directory count exceeds optional header", &fixture, EINVAL) == 0,
          "directory count beyond optional-header bytes is rejected");

    return 0;
}

static int test_malformed_image_ranges(void) {
    struct PEFixture fixture;
    const size_t text = SECTION_TABLE;
    const size_t data = SECTION_TABLE + 40u;

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 28, 0u);
    CHECK(expect_rejected("zero preferred base", &fixture, EINVAL) == 0,
          "zero preferred base is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 28, IMAGE_BASE + 0x1000u);
    CHECK(expect_rejected("unaligned preferred base", &fixture, EINVAL) == 0,
          "preferred base must satisfy guest granule alignment");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 28, 0xffffc000u);
    CHECK(expect_rejected("image crosses 4 GiB", &fixture, EINVAL) == 0,
          "preferred image range crossing 4 GiB is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 56, 0u);
    CHECK(expect_rejected("zero image size", &fixture, EINVAL) == 0,
          "zero-sized image is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 56, 64u * 1024u * 1024u + 1u);
    CHECK(expect_rejected("image above size limit", &fixture, EINVAL) == 0,
          "image above 64 MiB is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 16, IMAGE_SIZE);
    CHECK(expect_rejected("entry outside image", &fixture, EINVAL) == 0,
          "entry RVA at image end is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 16, BSS_RVA);
    put32(fixture.bytes + SECTION_TABLE + 2u * 40u + 36u, 0x60000020u);
    CHECK(expect_rejected("entry in BSS", &fixture, EINVAL) == 0,
          "entry point must be file-backed even in an executable section");

    make_fixture(&fixture);
    put32(fixture.bytes + text + 36, 0x40000020u);
    CHECK(expect_rejected("entry section not executable", &fixture, EINVAL) == 0,
          "entry section without execute permission is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 112, IMAGE_SIZE - 0x10u);
    put32(fixture.bytes + OPTIONAL_OFFSET + 116, 0x20u);
    CHECK(expect_rejected("resource directory crosses image", &fixture, EINVAL) == 0,
          "resource directory outside image bounds is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 116, 0u);
    CHECK(expect_rejected("resource directory size mismatch", &fixture, EINVAL) == 0,
          "resource RVA and size must be both present or both absent");

    make_fixture(&fixture);
    put32(fixture.bytes + OPTIONAL_OFFSET + 112, IMAGE_SIZE);
    put32(fixture.bytes + OPTIONAL_OFFSET + 116, 1u);
    CHECK(expect_rejected("resource starts at image end", &fixture, EINVAL) == 0,
          "resource range at image end is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + data + 12, TEXT_RVA + 0x80u);
    CHECK(expect_rejected("overlapping virtual sections", &fixture, EINVAL) == 0,
          "overlapping virtual section ranges are rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + text + 12, IMAGE_SIZE - 0x80u);
    CHECK(expect_rejected("virtual section exceeds image", &fixture, EINVAL) == 0,
          "virtual section range past SizeOfImage is rejected");

    make_fixture(&fixture);
    put32(fixture.bytes + text + 12, 0u);
    CHECK(expect_rejected("section overlaps headers", &fixture, EINVAL) == 0,
          "nonempty section cannot occupy image headers");

    make_fixture(&fixture);
    put32(fixture.bytes + text + 20, HEADER_SIZE - 1u);
    CHECK(expect_rejected("raw section starts in headers", &fixture, EINVAL) == 0,
          "raw section data cannot start within file headers");

    make_fixture(&fixture);
    put32(fixture.bytes + text + 20, UINT32_MAX - 15u);
    CHECK(expect_rejected("raw section exceeds input", &fixture, EINVAL) == 0,
          "raw section range outside source file is rejected");

    make_fixture(&fixture);
    put16(fixture.bytes + DOS_NT_OFFSET + 6, 0u);
    CHECK(expect_rejected("no sections", &fixture, EINVAL) == 0,
          "image without sections is rejected");

    make_fixture(&fixture);
    put16(fixture.bytes + DOS_NT_OFFSET + 6, 97u);
    CHECK(expect_rejected("too many sections", &fixture, EINVAL) == 0,
          "section count above 96 is rejected");

    return 0;
}

static int test_missing_arguments(void) {
    struct PEFixture fixture;
    GuestPEImage image;
    char diagnostic[128];

    make_fixture(&fixture);
    memset(&image, 0xa5, sizeof image);
    CHECK(guest_pe_load(NULL, 0, &image, diagnostic, sizeof diagnostic) == EINVAL,
          "null source is rejected");
    CHECK(is_zero_image(&image) && g_mem == NULL,
          "null-source failure leaves output clear and mapping absent");
    CHECK(guest_pe_load(fixture.bytes, fixture.length, NULL,
                        diagnostic, sizeof diagnostic) == EINVAL,
          "null output image is rejected");
    CHECK(g_mem == NULL, "null-output failure creates no mapping");
    return 0;
}

static int verify_valid_load(struct PEFixture *fixture) {
    GuestPEImage image;
    GuestPEImage busy_image;
    char diagnostic[256];
    uint8_t source_snapshot[FILE_SIZE];
    uint8_t *active_mem;
    uint8_t *headers, *text, *data, *bss, *gap;
    const uint64_t expected_commit =
        ((uint64_t)IMAGE_SIZE + GUEST_MEMORY_GRANULE - 1u) &
        ~(uint64_t)(GUEST_MEMORY_GRANULE - 1u);

    CHECK(g_mem == NULL, "valid load starts with no guest mapping");
    (void)memcpy(source_snapshot, fixture->bytes, sizeof source_snapshot);
    memset(&image, 0, sizeof image);
    diagnostic[0] = '\0';
    CHECK(guest_pe_load(fixture->bytes, fixture->length, &image,
                        diagnostic, sizeof diagnostic) == 0,
          "synthetic PE32 loads successfully");
    CHECK(g_mem != NULL, "successful load owns the guest mapping");
    CHECK(image.image_base == IMAGE_BASE && image.image_size == IMAGE_SIZE,
          "preferred base and unaligned SizeOfImage are preserved");
    CHECK(image.entry_point == IMAGE_BASE + ENTRY_RVA,
          "entry RVA is translated to the preferred guest address");
    CHECK(image.resource_address == IMAGE_BASE + RESOURCE_RVA &&
          image.resource_size == RESOURCE_SIZE,
          "resource directory is translated and reported");
    CHECK(image.section_count == SECTION_COUNT, "section count is reported");
    CHECK(diagnostic[0] == 'P', "successful load produces a pass diagnostic");
    CHECK(guest_memory_committed() == expected_commit,
          "the image range is committed with granule rounding");
    active_mem = g_mem;

    headers = (uint8_t *)guest_memory_pointer(IMAGE_BASE, HEADER_SIZE, 0);
    text = (uint8_t *)guest_memory_pointer(IMAGE_BASE + TEXT_RVA,
                                           TEXT_VIRTUAL_SIZE, 0);
    data = (uint8_t *)guest_memory_pointer(IMAGE_BASE + DATA_RVA,
                                           DATA_VIRTUAL_SIZE, 0);
    bss = (uint8_t *)guest_memory_pointer(IMAGE_BASE + BSS_RVA, BSS_SIZE, 0);
    gap = (uint8_t *)guest_memory_pointer(IMAGE_BASE + 0x2000u, 1, 0);
    CHECK(headers != NULL && text != NULL && data != NULL && bss != NULL && gap != NULL,
          "headers, section ranges, BSS and image gaps are addressable");
    CHECK(memcmp(headers, fixture->bytes, HEADER_SIZE) == 0,
          "file headers are copied byte-for-byte");
    for (unsigned i = 0; i < TEXT_VIRTUAL_SIZE; ++i) {
        CHECK(text[i] == text_byte(i), "text bytes are copied up to virtual size");
    }
    for (unsigned i = 0; i < DATA_VIRTUAL_SIZE; ++i) {
        CHECK(data[i] == data_byte(i), "data bytes are copied up to virtual size");
    }
    for (unsigned i = 0; i < BSS_SIZE; ++i) {
        CHECK(bss[i] == 0, "BSS remains zero-filled");
    }
    CHECK(*gap == 0, "unmapped image gap is zero-filled");
    CHECK(memcmp(fixture->bytes, source_snapshot, sizeof source_snapshot) == 0,
          "source fixture remains unchanged");

    memset(&busy_image, 0xa5, sizeof busy_image);
    CHECK(guest_pe_load(fixture->bytes, fixture->length, &busy_image,
                        diagnostic, sizeof diagnostic) == EBUSY,
          "loader refuses to replace an active runtime");
    CHECK(g_mem == active_mem && headers == active_mem + IMAGE_BASE &&
          guest_memory_committed() == expected_commit,
          "busy load preserves the active mapping and accounting");
    CHECK(text[0] == text_byte(0), "busy load preserves existing guest contents");
    CHECK(is_zero_image(&busy_image), "busy failure leaves its output clear");
    return 0;
}

int main(void) {
    struct PEFixture fixture;

    CHECK(sizeof(size_t) >= 8, "PE loader test requires a 64-bit host");
    CHECK(test_truncated_boundaries() == 0, "truncated-header cases pass");
    CHECK(test_malformed_headers() == 0, "malformed-header cases pass");
    CHECK(test_malformed_image_ranges() == 0, "malformed-range cases pass");
    CHECK(test_missing_arguments() == 0, "missing-argument cases pass");

    make_fixture(&fixture);
    CHECK(verify_valid_load(&fixture) == 0, "valid synthetic image loads and verifies");
    CHECK(guest_memory_shutdown() == 0, "first loaded image shuts down cleanly");
    CHECK(g_mem == NULL && guest_memory_committed() == 0,
          "shutdown clears image mapping and accounting");

    CHECK(verify_valid_load(&fixture) == 0,
          "valid image reloads after guest-memory shutdown");
    CHECK(guest_memory_shutdown() == 0, "reloaded image shuts down cleanly");
    CHECK(g_mem == NULL && guest_memory_committed() == 0,
          "final shutdown leaves no active guest mapping");

    puts("PASS guest PE loader");
    return 0;
}
