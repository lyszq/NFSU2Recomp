#include "guest_locale.h"
#include "guest_memory.h"
#include <stdint.h>
#include <string.h>
#include <strings.h>

#define C1_UPPER    0x0001
#define C1_LOWER    0x0002
#define C1_DIGIT    0x0004
#define C1_SPACE    0x0008
#define C1_PUNCT    0x0010
#define C1_CNTRL    0x0020
#define C1_BLANK    0x0040
#define C1_XDIGIT   0x0080
#define C1_ALPHA    0x0100
#define C1_DEFINED  0x0200

#define CT_CTYPE1   1

#define LCMAP_LOWERCASE 0x00000100
#define LCMAP_UPPERCASE 0x00000200

#define ERROR_INVALID_PARAMETER   87
#define ERROR_INSUFFICIENT_BUFFER 122

/*
 * Canonical Windows-1252 CT_CTYPE1 table for all 256 byte values.
 * Directly corresponds to Windows NLS GetStringTypeA(1033, CT_CTYPE1, ...).
 */
static const uint16_t g_ctype1_cp1252[256] = {
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, /* 0x00 - 0x07 */
    0x0220, 0x0268, 0x0228, 0x0228, 0x0228, 0x0228, 0x0220, 0x0220, /* 0x08 - 0x0F */
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, /* 0x10 - 0x17 */
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, /* 0x18 - 0x1F */
    0x0248, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x20 - 0x27 */
    0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x28 - 0x2F */
    0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, /* 0x30 - 0x37 */
    0x0284, 0x0284, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x38 - 0x3F */
    0x0210, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0301, /* 0x40 - 0x47 */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, /* 0x48 - 0x4F */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, /* 0x50 - 0x57 */
    0x0301, 0x0301, 0x0301, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x58 - 0x5F */
    0x0210, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0302, /* 0x60 - 0x67 */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, /* 0x68 - 0x6F */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, /* 0x70 - 0x77 */
    0x0302, 0x0302, 0x0302, 0x0210, 0x0210, 0x0210, 0x0210, 0x0220, /* 0x78 - 0x7F */
    0x0200, 0x0220, 0x0210, 0x0302, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x80 - 0x87 */
    0x0200, 0x0210, 0x0301, 0x0210, 0x0301, 0x0220, 0x0301, 0x0220, /* 0x88 - 0x8F */
    0x0220, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0x90 - 0x97 */
    0x0200, 0x0200, 0x0302, 0x0210, 0x0302, 0x0220, 0x0302, 0x0301, /* 0x98 - 0x9F */
    0x0248, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0xA0 - 0xA7 */
    0x0210, 0x0210, 0x0312, 0x0210, 0x0210, 0x0230, 0x0210, 0x0210, /* 0xA8 - 0xAF */
    0x0210, 0x0210, 0x0214, 0x0214, 0x0210, 0x0312, 0x0210, 0x0210, /* 0xB0 - 0xB7 */
    0x0210, 0x0214, 0x0312, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, /* 0xB8 - 0xBF */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, /* 0xC0 - 0xC7 */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, /* 0xC8 - 0xCF */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0210, /* 0xD0 - 0xD7 */
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0302, /* 0xD8 - 0xDF */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, /* 0xE0 - 0xE7 */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, /* 0xE8 - 0xEF */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0210, /* 0xF0 - 0xF7 */
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302  /* 0xF8 - 0xFF */
};

static int set_teb_last_error(CPU *cpu, uint32_t error_code, uint32_t *fault)
{
    if (!cpu || cpu->fs_base == 0U) {
        *fault = 0U;
        return -2;
    }
    const uint64_t teb_sum = (uint64_t)cpu->fs_base + 0x34ULL;
    if (teb_sum > (uint64_t)UINT32_MAX || teb_sum + 4ULL > 0x100000000ULL) {
        *fault = (uint32_t)teb_sum;
        return -1;
    }
    void *teb_ptr = guest_memory_pointer((uint32_t)teb_sum, 4ULL, 1);
    if (!teb_ptr) {
        *fault = (uint32_t)teb_sum;
        return -1;
    }
    memcpy(teb_ptr, &error_code, sizeof(uint32_t));
    return 0;
}

static uint16_t classify_wide_char(uint16_t wc)
{
    if (wc < 256U) {
        return g_ctype1_cp1252[wc];
    }
    /* Latin Extended-A / Unicode casing ranges */
    if ((wc >= 0x0100U && wc <= 0x017FU) || (wc >= 0x0180U && wc <= 0x024FU)) {
        if (wc == 0x0160U || wc == 0x0152U || wc == 0x017DU || wc == 0x0178U) {
            return C1_DEFINED | C1_ALPHA | C1_UPPER;
        }
        if (wc == 0x0161U || wc == 0x0153U || wc == 0x017EU) {
            return C1_DEFINED | C1_ALPHA | C1_LOWER;
        }
        /* Even values in Latin Extended-A are uppercase, odd are lowercase */
        return (wc & 1U) ? (C1_DEFINED | C1_ALPHA | C1_LOWER)
                         : (C1_DEFINED | C1_ALPHA | C1_UPPER);
    }
    if (wc >= 0x2000U && wc <= 0x206FU) {
        return C1_DEFINED | C1_PUNCT;
    }
    return C1_DEFINED;
}

static uint16_t map_wide_char(uint16_t wc, uint32_t map_flags)
{
    if (map_flags & LCMAP_LOWERCASE) {
        if (wc >= (uint16_t)'A' && wc <= (uint16_t)'Z') {
            return (uint16_t)(wc + 0x20U);
        }
        if ((wc >= 0x00C0U && wc <= 0x00D6U) || (wc >= 0x00D8U && wc <= 0x00DEU)) {
            return (uint16_t)(wc + 0x20U);
        }
        if (wc == 0x0160U) return 0x0161U; /* Š -> š */
        if (wc == 0x0152U) return 0x0153U; /* Œ -> œ */
        if (wc == 0x017DU) return 0x017EU; /* Ž -> ž */
        if (wc == 0x0178U) return 0x00FFU; /* Ÿ -> ÿ */
        /* Raw byte fallback if wide char is encoded as direct CP1252 byte */
        if (wc == 0x008AU) return 0x009AU;
        if (wc == 0x008CU) return 0x009CU;
        if (wc == 0x008EU) return 0x009EU;
        if (wc == 0x009FU) return 0x00FFU;
    } else if (map_flags & LCMAP_UPPERCASE) {
        if (wc >= (uint16_t)'a' && wc <= (uint16_t)'z') {
            return (uint16_t)(wc - 0x20U);
        }
        if ((wc >= 0x00E0U && wc <= 0x00F6U) || (wc >= 0x00F8U && wc <= 0x00FEU)) {
            return (uint16_t)(wc - 0x20U);
        }
        if (wc == 0x0161U) return 0x0160U; /* š -> Š */
        if (wc == 0x0153U) return 0x0152U; /* œ -> Œ */
        if (wc == 0x017EU) return 0x017DU; /* ž -> Ž */
        if (wc == 0x00FFU) return 0x0178U; /* ÿ -> Ÿ */
        /* Raw byte fallback */
        if (wc == 0x009AU) return 0x008AU;
        if (wc == 0x009CU) return 0x008CU;
        if (wc == 0x009EU) return 0x008EU;
    }
    return wc;
}

static uint8_t map_byte_char(uint8_t c, uint32_t map_flags)
{
    if (map_flags & LCMAP_LOWERCASE) {
        if (c >= (uint8_t)'A' && c <= (uint8_t)'Z') {
            return (uint8_t)(c + 0x20U);
        }
        if ((c >= 0xC0U && c <= 0xD6U) || (c >= 0xD8U && c <= 0xDEU)) {
            return (uint8_t)(c + 0x20U);
        }
        if (c == 0x8AU) return 0x9AU; /* Š -> š */
        if (c == 0x8CU) return 0x9CU; /* Œ -> œ */
        if (c == 0x8EU) return 0x9EU; /* Ž -> ž */
        if (c == 0x9FU) return 0xFFU; /* Ÿ -> ÿ */
    } else if (map_flags & LCMAP_UPPERCASE) {
        if (c >= (uint8_t)'a' && c <= (uint8_t)'z') {
            return (uint8_t)(c - 0x20U);
        }
        if ((c >= 0xE0U && c <= 0xF6U) || (c >= 0xF8U && c <= 0xFEU)) {
            return (uint8_t)(c - 0x20U);
        }
        if (c == 0x9AU) return 0x8AU; /* š -> Š */
        if (c == 0x9CU) return 0x8CU; /* œ -> Œ */
        if (c == 0x9EU) return 0x8EU; /* ž -> Ž */
        if (c == 0xFFU) return 0x9FU; /* ÿ -> Ÿ */
    }
    return c;
}

/*
 * GetCPInfo (IAT 0x007830c4, argc: 2)
 * BOOL GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
 *
 * Memory layout of CPINFO (18 bytes total):
 *   +0x00: UINT MaxCharSize (4 bytes: 1)
 *   +0x04: BYTE DefaultChar[2] (2 bytes: DefaultChar[0]='?', DefaultChar[1]=0)
 *   +0x06: BYTE LeadByte[12] (12 bytes: all zeros)
 */
static int handle_get_cp_info(CPU *cpu, uint32_t ret_ip, uint32_t code_page,
                              uint32_t lp_cp_info, uint32_t *fault)
{
    if (lp_cp_info == 0U) {
        *fault = 0U;
        return -1;
    }

    void *out = guest_memory_pointer(lp_cp_info, 18ULL, 1);
    if (!out) {
        *fault = lp_cp_info;
        return -1;
    }

    /* CodePage 0 (CP_ACP), 1 (CP_OEMCP), 1252 (Latin-1), or 437 (OEM) */
    if (code_page != 0U && code_page != 1U && code_page != 1252U && code_page != 437U) {
        int err_rc = set_teb_last_error(cpu, ERROR_INVALID_PARAMETER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 12U;
        return 1;
    }

    uint8_t cpinfo[18];
    memset(cpinfo, 0, sizeof(cpinfo));

    /* MaxCharSize = 1 */
    const uint32_t max_char_size = 1U;
    memcpy(cpinfo + 0, &max_char_size, sizeof(max_char_size));

    /* DefaultChar = '?' (0x3F), DefaultChar[1] = 0 */
    cpinfo[4] = (uint8_t)'?';
    cpinfo[5] = 0U;

    /* LeadByte[12] = [0] * 12 (already zeroed by memset) */

    memcpy(out, cpinfo, sizeof(cpinfo));

    cpu->eax = 1U; /* TRUE */
    cpu->eip = ret_ip;
    cpu->esp += 12U;
    return 1;
}

/*
 * GetStringTypeW (IAT 0x00783080, argc: 4)
 * BOOL GetStringTypeW(DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType)
 */
static int handle_get_string_type_w(CPU *cpu, uint32_t ret_ip, uint32_t dw_info_type,
                                    uint32_t lp_src, int32_t cch_src,
                                    uint32_t lp_char_type, uint32_t *fault)
{
    if (dw_info_type != CT_CTYPE1 || cch_src == 0 || cch_src < -1) {
        int err_rc = set_teb_last_error(cpu, ERROR_INVALID_PARAMETER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 20U;
        return 1;
    }

    if (lp_src == 0U) {
        *fault = 0U;
        return -1;
    }
    if (lp_char_type == 0U) {
        *fault = 0U;
        return -1;
    }

    uint32_t count = 0U;
    if (cch_src == -1) {
        /* Null-terminated UTF-16 string; count includes terminating null */
        while (1) {
            uint64_t addr = (uint64_t)lp_src + (uint64_t)count * 2ULL;
            if (addr + 2ULL > 0x100000000ULL) {
                *fault = (uint32_t)addr;
                return -1;
            }
            const void *p = guest_memory_pointer((uint32_t)addr, 2ULL, 0);
            if (!p) {
                *fault = (uint32_t)addr;
                return -1;
            }
            uint16_t wc = 0U;
            memcpy(&wc, p, sizeof(wc));
            count++;
            if (wc == 0U) {
                break;
            }
        }
    } else {
        count = (uint32_t)cch_src;
    }

    uint64_t src_bytes = (uint64_t)count * 2ULL;
    uint64_t dst_bytes = (uint64_t)count * 2ULL;

    const void *src_ptr = guest_memory_pointer(lp_src, src_bytes, 0);
    if (!src_ptr) {
        *fault = lp_src;
        return -1;
    }

    void *dst_ptr = guest_memory_pointer(lp_char_type, dst_bytes, 1);
    if (!dst_ptr) {
        *fault = lp_char_type;
        return -1;
    }

    const uint8_t *src_bytes_ptr = (const uint8_t *)src_ptr;
    uint8_t *dst_bytes_ptr = (uint8_t *)dst_ptr;

    for (uint32_t i = 0U; i < count; i++) {
        uint16_t wc = 0U;
        memcpy(&wc, src_bytes_ptr + i * 2U, sizeof(wc));
        uint16_t ct = classify_wide_char(wc);
        memcpy(dst_bytes_ptr + i * 2U, &ct, sizeof(ct));
    }

    cpu->eax = 1U;
    cpu->eip = ret_ip;
    cpu->esp += 20U;
    return 1;
}

/*
 * GetStringTypeA (IAT 0x00783084, argc: 5)
 * BOOL GetStringTypeA(LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType)
 */
static int handle_get_string_type_a(CPU *cpu, uint32_t ret_ip, uint32_t dw_info_type,
                                    uint32_t lp_src, int32_t cch_src,
                                    uint32_t lp_char_type, uint32_t *fault)
{
    if (dw_info_type != CT_CTYPE1 || cch_src == 0 || cch_src < -1) {
        int err_rc = set_teb_last_error(cpu, ERROR_INVALID_PARAMETER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 24U;
        return 1;
    }

    if (lp_src == 0U) {
        *fault = 0U;
        return -1;
    }
    if (lp_char_type == 0U) {
        *fault = 0U;
        return -1;
    }

    uint32_t count = 0U;
    if (cch_src == -1) {
        while (1) {
            uint64_t addr = (uint64_t)lp_src + (uint64_t)count;
            if (addr + 1ULL > 0x100000000ULL) {
                *fault = (uint32_t)addr;
                return -1;
            }
            const void *p = guest_memory_pointer((uint32_t)addr, 1ULL, 0);
            if (!p) {
                *fault = (uint32_t)addr;
                return -1;
            }
            uint8_t c = *(const uint8_t *)p;
            count++;
            if (c == 0U) {
                break;
            }
        }
    } else {
        count = (uint32_t)cch_src;
    }

    const void *src_ptr = guest_memory_pointer(lp_src, (uint64_t)count, 0);
    if (!src_ptr) {
        *fault = lp_src;
        return -1;
    }

    void *dst_ptr = guest_memory_pointer(lp_char_type, (uint64_t)count * 2ULL, 1);
    if (!dst_ptr) {
        *fault = lp_char_type;
        return -1;
    }

    const uint8_t *src_bytes = (const uint8_t *)src_ptr;
    uint8_t *dst_bytes = (uint8_t *)dst_ptr;

    for (uint32_t i = 0U; i < count; i++) {
        uint8_t c = src_bytes[i];
        uint16_t ct = g_ctype1_cp1252[c];
        memcpy(dst_bytes + i * 2U, &ct, sizeof(ct));
    }

    cpu->eax = 1U;
    cpu->eip = ret_ip;
    cpu->esp += 24U;
    return 1;
}

/*
 * LCMapStringW (IAT 0x007830b8, argc: 6)
 * int LCMapStringW(LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc,
 *                  LPWSTR lpDestStr, int cchDest)
 */
static int handle_lc_map_string_w(CPU *cpu, uint32_t ret_ip, uint32_t dw_map_flags,
                                  uint32_t lp_src, int32_t cch_src,
                                  uint32_t lp_dest, int32_t cch_dest, uint32_t *fault)
{
    if (cch_src == 0 || cch_src < -1) {
        int err_rc = set_teb_last_error(cpu, ERROR_INVALID_PARAMETER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if (lp_src == 0U) {
        *fault = 0U;
        return -1;
    }

    uint32_t count = 0U;
    if (cch_src == -1) {
        while (1) {
            uint64_t addr = (uint64_t)lp_src + (uint64_t)count * 2ULL;
            if (addr + 2ULL > 0x100000000ULL) {
                *fault = (uint32_t)addr;
                return -1;
            }
            const void *p = guest_memory_pointer((uint32_t)addr, 2ULL, 0);
            if (!p) {
                *fault = (uint32_t)addr;
                return -1;
            }
            uint16_t wc = 0U;
            memcpy(&wc, p, sizeof(wc));
            count++;
            if (wc == 0U) {
                break;
            }
        }
    } else {
        count = (uint32_t)cch_src;
    }

    const void *src_ptr = guest_memory_pointer(lp_src, (uint64_t)count * 2ULL, 0);
    if (!src_ptr) {
        *fault = lp_src;
        return -1;
    }

    /* Size query mode */
    if (cch_dest == 0) {
        cpu->eax = count;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if ((uint32_t)cch_dest < count) {
        int err_rc = set_teb_last_error(cpu, ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if (lp_dest == 0U) {
        *fault = 0U;
        return -1;
    }

    void *dst_ptr = guest_memory_pointer(lp_dest, (uint64_t)count * 2ULL, 1);
    if (!dst_ptr) {
        *fault = lp_dest;
        return -1;
    }

    const uint8_t *src_bytes = (const uint8_t *)src_ptr;
    uint8_t *dst_bytes = (uint8_t *)dst_ptr;

    for (uint32_t i = 0U; i < count; i++) {
        uint16_t wc = 0U;
        memcpy(&wc, src_bytes + i * 2U, sizeof(wc));
        uint16_t mapped = map_wide_char(wc, dw_map_flags);
        memcpy(dst_bytes + i * 2U, &mapped, sizeof(mapped));
    }

    cpu->eax = count;
    cpu->eip = ret_ip;
    cpu->esp += 28U;
    return 1;
}

/*
 * LCMapStringA (IAT 0x007830bc, argc: 6)
 * int LCMapStringA(LCID Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, int cchSrc,
 *                  LPSTR lpDestStr, int cchDest)
 */
static int handle_lc_map_string_a(CPU *cpu, uint32_t ret_ip, uint32_t dw_map_flags,
                                  uint32_t lp_src, int32_t cch_src,
                                  uint32_t lp_dest, int32_t cch_dest, uint32_t *fault)
{
    if (cch_src == 0 || cch_src < -1) {
        int err_rc = set_teb_last_error(cpu, ERROR_INVALID_PARAMETER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if (lp_src == 0U) {
        *fault = 0U;
        return -1;
    }

    uint32_t count = 0U;
    if (cch_src == -1) {
        while (1) {
            uint64_t addr = (uint64_t)lp_src + (uint64_t)count;
            if (addr + 1ULL > 0x100000000ULL) {
                *fault = (uint32_t)addr;
                return -1;
            }
            const void *p = guest_memory_pointer((uint32_t)addr, 1ULL, 0);
            if (!p) {
                *fault = (uint32_t)addr;
                return -1;
            }
            uint8_t c = *(const uint8_t *)p;
            count++;
            if (c == 0U) {
                break;
            }
        }
    } else {
        count = (uint32_t)cch_src;
    }

    const void *src_ptr = guest_memory_pointer(lp_src, (uint64_t)count, 0);
    if (!src_ptr) {
        *fault = lp_src;
        return -1;
    }

    if (cch_dest == 0) {
        cpu->eax = count;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if ((uint32_t)cch_dest < count) {
        int err_rc = set_teb_last_error(cpu, ERROR_INSUFFICIENT_BUFFER, fault);
        if (err_rc != 0) {
            return err_rc;
        }
        cpu->eax = 0U;
        cpu->eip = ret_ip;
        cpu->esp += 28U;
        return 1;
    }

    if (lp_dest == 0U) {
        *fault = 0U;
        return -1;
    }

    void *dst_ptr = guest_memory_pointer(lp_dest, (uint64_t)count, 1);
    if (!dst_ptr) {
        *fault = lp_dest;
        return -1;
    }

    const uint8_t *src_bytes = (const uint8_t *)src_ptr;
    uint8_t *dst_bytes = (uint8_t *)dst_ptr;

    for (uint32_t i = 0U; i < count; i++) {
        dst_bytes[i] = map_byte_char(src_bytes[i], dw_map_flags);
    }

    cpu->eax = count;
    cpu->eip = ret_ip;
    cpu->esp += 28U;
    return 1;
}

int guest_locale_import(CPU *cpu, const GuestImport *imp, uint32_t *fault)
{
    if (!cpu || !imp || !fault || !imp->name || !imp->library) {
        return 0;
    }

    if (strcasecmp(imp->library, "KERNEL32.dll") != 0) {
        return 0;
    }

    const int is_get_cp_info = (strcmp(imp->name, "GetCPInfo") == 0);
    const int is_get_string_type_w = (strcmp(imp->name, "GetStringTypeW") == 0);
    const int is_get_string_type_a = (strcmp(imp->name, "GetStringTypeA") == 0);
    const int is_lc_map_string_w = (strcmp(imp->name, "LCMapStringW") == 0);
    const int is_lc_map_string_a = (strcmp(imp->name, "LCMapStringA") == 0);

    if (!is_get_cp_info && !is_get_string_type_w && !is_get_string_type_a &&
        !is_lc_map_string_w && !is_lc_map_string_a) {
        return 0;
    }

    uint32_t argc = 0U;
    if (is_get_cp_info) argc = 2U;
    else if (is_get_string_type_w) argc = 4U;
    else if (is_get_string_type_a) argc = 5U;
    else if (is_lc_map_string_w || is_lc_map_string_a) argc = 6U;

    const uint64_t frame_bytes = (uint64_t)(argc + 1U) * 4ULL;
    if ((uint64_t)cpu->esp + frame_bytes > 0x100000000ULL) {
        *fault = cpu->esp;
        return -1;
    }

    const void *frame_ptr = guest_memory_pointer(cpu->esp, frame_bytes, 0);
    if (!frame_ptr) {
        *fault = cpu->esp;
        return -1;
    }

    uint32_t frame[7];
    memcpy(frame, frame_ptr, (size_t)frame_bytes);

    const uint32_t ret_ip = frame[0];

    if (is_get_cp_info) {
        const uint32_t code_page = frame[1];
        const uint32_t lp_cp_info = frame[2];
        return handle_get_cp_info(cpu, ret_ip, code_page, lp_cp_info, fault);
    }

    if (is_get_string_type_w) {
        const uint32_t dw_info_type = frame[1];
        const uint32_t lp_src = frame[2];
        const int32_t cch_src = (int32_t)frame[3];
        const uint32_t lp_char_type = frame[4];
        return handle_get_string_type_w(cpu, ret_ip, dw_info_type, lp_src, cch_src, lp_char_type, fault);
    }

    if (is_get_string_type_a) {
        const uint32_t dw_info_type = frame[2];
        const uint32_t lp_src = frame[3];
        const int32_t cch_src = (int32_t)frame[4];
        const uint32_t lp_char_type = frame[5];
        return handle_get_string_type_a(cpu, ret_ip, dw_info_type, lp_src, cch_src, lp_char_type, fault);
    }

    if (is_lc_map_string_w) {
        const uint32_t dw_map_flags = frame[2];
        const uint32_t lp_src = frame[3];
        const int32_t cch_src = (int32_t)frame[4];
        const uint32_t lp_dest = frame[5];
        const int32_t cch_dest = (int32_t)frame[6];
        return handle_lc_map_string_w(cpu, ret_ip, dw_map_flags, lp_src, cch_src, lp_dest, cch_dest, fault);
    }

    if (is_lc_map_string_a) {
        const uint32_t dw_map_flags = frame[2];
        const uint32_t lp_src = frame[3];
        const int32_t cch_src = (int32_t)frame[4];
        const uint32_t lp_dest = frame[5];
        const int32_t cch_dest = (int32_t)frame[6];
        return handle_lc_map_string_a(cpu, ret_ip, dw_map_flags, lp_src, cch_src, lp_dest, cch_dest, fault);
    }

    return 0;
}
