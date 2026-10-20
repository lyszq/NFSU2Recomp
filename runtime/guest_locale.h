#ifndef NFSU2_GUEST_LOCALE_H
#define NFSU2_GUEST_LOCALE_H

#include "guest_execution.h"

/*
 * Guest Windows XP CRT Locale, Codepage, and Character Mapping subsystem.
 *
 * Implements KERNEL32 exports required during CRT multibyte initialization (_setmbcp):
 *
 * 1. GetCPInfo (IAT 0x007830c4, argc: 2: UINT CodePage, LPCPINFO lpCPInfo)
 *    - CodePage 0 (CP_ACP) / 1252: Single-byte Windows-1252 Latin-1.
 *      MaxCharSize = 1, DefaultChar = '?' (0x3F), LeadByte = [0] * 12.
 *    - CodePage 1 (CP_OEMCP) / 437: Single-byte OEM US-ASCII.
 *      MaxCharSize = 1, DefaultChar = '?' (0x3F), LeadByte = [0] * 12.
 *    - Invalid CodePage sets LastError 87 (ERROR_INVALID_PARAMETER) and returns FALSE.
 *
 * 2. GetStringTypeW (IAT 0x00783080, argc: 4: DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType)
 *    GetStringTypeA (IAT 0x00783084, argc: 5: LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType)
 *    - Implements dwInfoType = 1 (CT_CTYPE1) bitmask classifications:
 *      C1_UPPER (0x0001), C1_LOWER (0x0002), C1_DIGIT (0x0004), C1_SPACE (0x0008),
 *      C1_PUNCT (0x0010), C1_CNTRL (0x0020), C1_BLANK (0x0040), C1_XDIGIT (0x0080),
 *      C1_ALPHA (0x0100), C1_DEFINED (0x0200).
 *    - Preserves LastError on success.
 *
 * 3. LCMapStringW (IAT 0x007830b8, argc: 6: LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest)
 *    LCMapStringA (IAT 0x007830bc, argc: 6: LCID Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest)
 *    - Implements LCMAP_LOWERCASE (0x00000100) and LCMAP_UPPERCASE (0x00000200).
 *    - cchDest == 0 performs buffer size query (returns required wide/byte char count).
 *    - cchDest > 0 performs case conversion into guest destination buffer.
 *    - Preserves LastError on success; sets LastError 122 (ERROR_INSUFFICIENT_BUFFER) if buffer too small.
 *
 * All functions validate whole stack frame before mutating registers or memory.
 * Faulting accesses return -1 with *fault set. Unsupported library/name returns 0.
 */

int guest_locale_import(CPU *cpu, const GuestImport *imp, uint32_t *fault);

#endif /* NFSU2_GUEST_LOCALE_H */
