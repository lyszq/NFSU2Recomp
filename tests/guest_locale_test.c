#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "cpu.h"
#include "guest_memory.h"
#include "guest_locale.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define STACK_ADDR 0x10000u
#define TEB_ADDR   0x30000u
#define BUF_ADDR   0x40000u
#define RET_ADDR   0x00401234u

static int write_u32(uint32_t addr, uint32_t val) {
    void *p = guest_memory_pointer(addr, sizeof(val), 1);
    CHECK(p != NULL);
    memcpy(p, &val, sizeof(val));
    return 0;
}

static uint32_t read_u32(uint32_t addr) {
    void *p = guest_memory_pointer(addr, sizeof(uint32_t), 0);
    if (!p) return 0xFFFFFFFFu;
    uint32_t val = 0;
    memcpy(&val, p, sizeof(val));
    return val;
}

static void init_cpu(CPU *cpu, uint32_t esp, uint32_t fs) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->eax = 0x11111111u;
    cpu->ecx = 0x22222222u;
    cpu->edx = 0x33333333u;
    cpu->ebx = 0x44444444u;
    cpu->esp = esp;
    cpu->ebp = 0x55555555u;
    cpu->esi = 0x66666666u;
    cpu->edi = 0x77777777u;
    cpu->eip = 0x88888888u;
    cpu->fs_base = fs;
    cpu->gs_base = 0x99999999u;
}

static int test_get_cp_info(void) {
    CPU cpu;
    uint32_t fault = 0;
    GuestImport imp = { 0x007830c4, "KERNEL32.dll", "GetCPInfo" };

    /* 1. CP 1252 valid call */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 1252);
    write_u32(STACK_ADDR + 8, BUF_ADDR);

    int rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == STACK_ADDR + 12);

    /* Verify CPINFO layout: MaxCharSize=1, DefaultChar='?', LeadByte=[0]*12 */
    void *p = guest_memory_pointer(BUF_ADDR, 18, 0);
    CHECK(p != NULL);
    uint32_t max_char_size = 0;
    memcpy(&max_char_size, p, 4);
    CHECK(max_char_size == 1);
    const uint8_t *b = (const uint8_t *)p;
    CHECK(b[4] == (uint8_t)'?');
    CHECK(b[5] == 0);
    for (int i = 6; i < 18; i++) {
        CHECK(b[i] == 0);
    }

    /* 2. CP 0 (CP_ACP) valid call */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0);
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);

    /* 3. Invalid CodePage (99999) -> returns 0, LastError = 87 */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_u32(TEB_ADDR + 0x34, 0);
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 99999);
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 0);
    CHECK(read_u32(TEB_ADDR + 0x34) == 87);

    return 0;
}

static int test_get_string_type_w(void) {
    CPU cpu;
    uint32_t fault = 0;
    GuestImport imp = { 0x00783080, "KERNEL32.dll", "GetStringTypeW" };

    /* Probe with L" " */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    uint16_t space_str[2] = { (uint16_t)' ', 0 };
    void *sp = guest_memory_pointer(BUF_ADDR, 4, 1);
    memcpy(sp, space_str, 4);

    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 1); /* CT_CTYPE1 */
    write_u32(STACK_ADDR + 8, BUF_ADDR);
    write_u32(STACK_ADDR + 12, 1); /* cchSrc = 1 */
    write_u32(STACK_ADDR + 16, BUF_ADDR + 0x100);

    int rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 1);
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == STACK_ADDR + 20);

    uint16_t out_type = 0;
    void *op = guest_memory_pointer(BUF_ADDR + 0x100, 2, 0);
    memcpy(&out_type, op, 2);
    /* Space should have C1_SPACE (0x0008) | C1_BLANK (0x0040) | C1_DEFINED (0x0200) = 0x0248 */
    CHECK(out_type == 0x0248);

    return 0;
}

static int test_lc_map_string_w(void) {
    CPU cpu;
    uint32_t fault = 0;
    GuestImport imp = { 0x007830b8, "KERNEL32.dll", "LCMapStringW" };

    /* 1. Size query with L" " and LCMAP_LOWERCASE (cchDest = 0) */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    uint16_t test_wstr[4] = { 'A', 'B', 'C', 0 };
    void *sp = guest_memory_pointer(BUF_ADDR, 8, 1);
    memcpy(sp, test_wstr, 8);

    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0); /* Locale */
    write_u32(STACK_ADDR + 8, 0x00000100); /* LCMAP_LOWERCASE */
    write_u32(STACK_ADDR + 12, BUF_ADDR);
    write_u32(STACK_ADDR + 16, 3); /* cchSrc = 3 */
    write_u32(STACK_ADDR + 20, 0); /* lpDest = 0 */
    write_u32(STACK_ADDR + 24, 0); /* cchDest = 0 */

    int rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 3); /* Query returns 3 */
    CHECK(cpu.eip == RET_ADDR);
    CHECK(cpu.esp == STACK_ADDR + 28);

    /* 2. Conversion: "ABC" -> "abc" */
    init_cpu(&cpu, STACK_ADDR, TEB_ADDR);
    write_u32(STACK_ADDR + 0, RET_ADDR);
    write_u32(STACK_ADDR + 4, 0);
    write_u32(STACK_ADDR + 8, 0x00000100); /* LCMAP_LOWERCASE */
    write_u32(STACK_ADDR + 12, BUF_ADDR);
    write_u32(STACK_ADDR + 16, 3);
    write_u32(STACK_ADDR + 20, BUF_ADDR + 0x200);
    write_u32(STACK_ADDR + 24, 3);

    rc = guest_locale_import(&cpu, &imp, &fault);
    CHECK(rc == 1);
    CHECK(cpu.eax == 3);

    uint16_t out_wstr[3];
    void *op = guest_memory_pointer(BUF_ADDR + 0x200, 6, 0);
    memcpy(out_wstr, op, 6);
    CHECK(out_wstr[0] == 'a');
    CHECK(out_wstr[1] == 'b');
    CHECK(out_wstr[2] == 'c');

    return 0;
}

int main(void) {
    if (guest_memory_init() != 0) {
        fprintf(stderr, "guest_memory_init failed\n");
        return 1;
    }
    guest_memory_commit(0, 0x100000);

    printf("Running test_get_cp_info...\n");
    if (test_get_cp_info() != 0) return 1;

    printf("Running test_get_string_type_w...\n");
    if (test_get_string_type_w() != 0) return 1;

    printf("Running test_lc_map_string_w...\n");
    if (test_lc_map_string_w() != 0) return 1;

    printf("ALL GUEST_LOCALE TESTS PASSED!\n");
    return 0;
}
