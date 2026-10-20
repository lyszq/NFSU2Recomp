#include "guest_windows.h"
#include "guest_memory.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define CHECK(x) do { \
    if (!(x)) { \
        fprintf(stderr, "FAIL WideCharToMultiByte test line %d: %s\n", __LINE__, #x); \
        return 1; \
    } \
} while (0)

#define STACK       0x10000u
#define BUFFER_SRC  0x20000u
#define BUFFER_DST  0x24000u
#define BUFFER_MISC 0x28000u
#define TEB         0x30000u

static void put32(uint32_t a, uint32_t v) { memcpy(g_mem + a, &v, 4); }
static uint32_t get32(uint32_t a) { uint32_t v; memcpy(&v, g_mem + a, 4); return v; }
static void put16(uint32_t a, uint16_t v) { memcpy(g_mem + a, &v, 2); }
static uint16_t get16(uint32_t a) { uint16_t v; memcpy(&v, g_mem + a, 2); return v; }

static CPU setup_cpu(void) {
    CPU c = {0};
    c.esp = STACK;
    c.fs_base = TEB;
    c.ebx = 0xbad12345u;
    c.ecx = 0xabcdef12u;
    c.edx = 0x11223344u;
    c.esi = 0x55667788u;
    c.edi = 0x99aabbccu;
    c.ebp = 0xddeeff00u;
    put32(STACK, 0x401005u); /* Return EIP */
    put32(TEB + 0x34, 999);  /* Initial LastError to verify preservation */
    return c;
}

static void push_args(uint32_t esp,
                      uint32_t code_page,
                      uint32_t dw_flags,
                      uint32_t lp_wide_char_str,
                      int32_t  cch_wide_char,
                      uint32_t lp_multi_byte_str,
                      int32_t  cb_multi_byte,
                      uint32_t lp_default_char,
                      uint32_t lp_used_default_char) {
    put32(esp + 4,  code_page);
    put32(esp + 8,  dw_flags);
    put32(esp + 12, lp_wide_char_str);
    put32(esp + 16, (uint32_t)cch_wide_char);
    put32(esp + 20, lp_multi_byte_str);
    put32(esp + 24, (uint32_t)cb_multi_byte);
    put32(esp + 28, lp_default_char);
    put32(esp + 32, lp_used_default_char);
}

int main(void) {
    CHECK(!guest_memory_init());
    CHECK(!guest_memory_commit(STACK, 0x30000));

    GuestWindows windows = {.image_base = 0x400000u};
    GuestImport api = {0, "KERNEL32.dll", "WideCharToMultiByte"};
    uint32_t fault = 0;

    /* Hazirlik: "Hello World\0" UTF-16 dizisi (11 karakter + 1 null = 12) */
    const char *text = "Hello World";
    for (int i = 0; i < 11; i++) {
        put16(BUFFER_SRC + 2 * i, (uint16_t)text[i]);
    }
    put16(BUFFER_SRC + 22, 0);

    /* --- TEST 1: Query Modu (cchWideChar = -1, cbMultiByte = 0) --- */
    {
        CPU c = setup_cpu(), before = c;
        push_args(STACK, 0, 0, BUFFER_SRC, -1, 0, 0, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 12); /* 11 karakter + 1 null */
        CHECK(c.esp == STACK + 36);
        CHECK(c.eip == 0x401005u);
        CHECK(c.ebx == before.ebx && c.esi == before.esi && c.edi == before.edi && c.ebp == before.ebp);
        CHECK(get32(TEB + 0x34) == 999); /* LastError degismemeli */
    }

    /* --- TEST 2: Query Modu (Belirli Uzunluk: cchWideChar = 5) --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, 5, 0, 0, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 5);
        CHECK(c.esp == STACK + 36);
        CHECK(get32(TEB + 0x34) == 999);
    }

    /* --- TEST 3: Convert Modu (cchWideChar = -1, cbMultiByte = 32) --- */
    {
        memset(g_mem + BUFFER_DST, 0xAA, 32);
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, -1, BUFFER_DST, 32, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 12);
        CHECK(c.esp == STACK + 36);
        CHECK(!memcmp(g_mem + BUFFER_DST, "Hello World\0", 12));
        CHECK(g_mem[BUFFER_DST + 12] == 0xAA); /* Fazla alana dokunulmamali */
        CHECK(get32(TEB + 0x34) == 999);
    }

    /* --- TEST 4: Convert Modu (Belirli Uzunluk: cchWideChar = 5, cbMultiByte = 16) --- */
    {
        memset(g_mem + BUFFER_DST, 0xBB, 16);
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, 5, BUFFER_DST, 16, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 5);
        CHECK(!memcmp(g_mem + BUFFER_DST, "Hello", 5));
        CHECK(g_mem[BUFFER_DST + 5] == 0xBB);
        CHECK(get32(TEB + 0x34) == 999);
    }

    /* --- TEST 5: Insufficient Buffer (cbMultiByte = 5 < 12) -> ERROR_INSUFFICIENT_BUFFER (122) --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, -1, BUFFER_DST, 5, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 0);
        CHECK(c.esp == STACK + 36);
        CHECK(get32(TEB + 0x34) == 122); /* ERROR_INSUFFICIENT_BUFFER */
    }

    /* --- TEST 6: Invalid Parameter: lpWideCharStr == 0 -> ERROR_INVALID_PARAMETER (87) --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, 0, -1, BUFFER_DST, 32, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 0);
        CHECK(get32(TEB + 0x34) == 87);
    }

    /* --- TEST 7: Invalid Parameter: cchWideChar == 0 -> ERROR_INVALID_PARAMETER (87) --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, 0, BUFFER_DST, 32, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 0);
        CHECK(get32(TEB + 0x34) == 87);
    }

    /* --- TEST 8: Invalid Parameter: cbMultiByte < 0 -> ERROR_INVALID_PARAMETER (87) --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, -1, BUFFER_DST, -5, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 0);
        CHECK(get32(TEB + 0x34) == 87);
    }

    /* --- TEST 9: CP1252 Ozel Karakter Donusumu (€ 0x20AC -> 0x80, ™ 0x2122 -> 0x99) --- */
    {
        put16(BUFFER_SRC, 0x20AC);     /* Euro */
        put16(BUFFER_SRC + 2, 0x2122); /* Trademark */
        put16(BUFFER_SRC + 4, 0);
        CPU c = setup_cpu();
        push_args(STACK, 1252, 0, BUFFER_SRC, -1, BUFFER_DST, 16, 0, 0);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 3);
        CHECK(g_mem[BUFFER_DST] == 0x80);
        CHECK(g_mem[BUFFER_DST + 1] == 0x99);
        CHECK(g_mem[BUFFER_DST + 2] == 0x00);
    }

    /* --- TEST 10: Unmapped Karakter ve lpUsedDefaultChar Kontrolu --- */
    {
        put16(BUFFER_SRC, 0x03A9); /* Greek Omega Ω (CP1252'de yok) */
        put16(BUFFER_SRC + 2, 0);
        put32(BUFFER_MISC, 0); /* lpUsedDefaultChar */
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, BUFFER_SRC, -1, BUFFER_DST, 16, 0, BUFFER_MISC);
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == 1);
        CHECK(c.eax == 2);
        CHECK(g_mem[BUFFER_DST] == '?');
        CHECK(get32(BUFFER_MISC) == 1); /* Default karakter kullanildi */
    }

    /* --- TEST 11: fs_base == 0 iken Hata -> -2 API State Stop --- */
    {
        CPU c = setup_cpu();
        c.fs_base = 0; /* Gecersiz TEB */
        push_args(STACK, 0, 0, 0, -1, BUFFER_DST, 32, 0, 0); /* Gecersiz parametre */
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == -2);
    }

    /* --- TEST 12: Memory Fault Testi --- */
    {
        CPU c = setup_cpu();
        push_args(STACK, 0, 0, 0x90000000u, -1, BUFFER_DST, 32, 0, 0); /* Haritalanmamis bellek */
        CHECK(guest_windows_import(&c, &api, &windows, &fault) == -1);
        CHECK(fault == 0x90000000u);
    }

    /* --- TEST 13: MultiByteToWideChar Testi --- */
    {
        GuestImport mb_api = {0, "KERNEL32.dll", "MultiByteToWideChar"};
        memcpy(g_mem + BUFFER_SRC, "NFSU2\0", 6);
        CPU c = setup_cpu();
        put32(STACK + 4, 0); /* CodePage */
        put32(STACK + 8, 0); /* Flags */
        put32(STACK + 12, BUFFER_SRC);
        put32(STACK + 16, (uint32_t)-1);
        put32(STACK + 20, BUFFER_DST);
        put32(STACK + 24, 16);
        CHECK(guest_windows_import(&c, &mb_api, &windows, &fault) == 1);
        CHECK(c.eax == 6);
        CHECK(c.esp == STACK + 28);
        CHECK(get16(BUFFER_DST) == 'N');
        CHECK(get16(BUFFER_DST + 2) == 'F');
        CHECK(get16(BUFFER_DST + 4) == 'S');
        CHECK(get16(BUFFER_DST + 6) == 'U');
        CHECK(get16(BUFFER_DST + 8) == '2');
        CHECK(get16(BUFFER_DST + 10) == 0);
    }

    /* --- TEST 14: GetModuleFileNameA Testi --- */
    {
        GuestImport mod_api = {0, "KERNEL32.dll", "GetModuleFileNameA"};
        CPU c = setup_cpu();
        put32(STACK + 4, 0); /* hModule == NULL */
        put32(STACK + 8, BUFFER_DST);
        put32(STACK + 12, 260);
        CHECK(guest_windows_import(&c, &mod_api, &windows, &fault) == 1);
        CHECK(c.eax == 19);
        CHECK(c.esp == STACK + 16);
        CHECK(!strcmp((const char *)(g_mem + BUFFER_DST), "C:\\NFSU2\\SPEED2.EXE"));
        CHECK(get32(TEB + 0x34) == 999); /* Basarili cagri LastError'i korur */

        /* Yanlis hModule -> LastError 126 */
        c = setup_cpu();
        put32(STACK + 4, 0x12340000u);
        put32(STACK + 8, BUFFER_DST);
        put32(STACK + 12, 260);
        CHECK(guest_windows_import(&c, &mod_api, &windows, &fault) == 1);
        CHECK(c.eax == 0);
        CHECK(get32(TEB + 0x34) == 126);

        /* Kucuk tampon -> LastError 122 */
        c = setup_cpu();
        put32(STACK + 4, 0);
        put32(STACK + 8, BUFFER_DST);
        put32(STACK + 12, 10);
        CHECK(guest_windows_import(&c, &mod_api, &windows, &fault) == 1);
        CHECK(c.eax == 10);
        CHECK(get32(TEB + 0x34) == 122);
    }

    CHECK(!guest_windows_cleanup(&windows));
    CHECK(!guest_memory_shutdown());
    puts("PASS | WideCharToMultiByte, MultiByteToWideChar & GetModuleFileNameA contracts");
    return 0;
}
