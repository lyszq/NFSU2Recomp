#include "guest_windows.h"
#include "guest_memory.h"
#include "guest_startup.h"
#include "guest_error.h"
#include "guest_stdio.h"
#include "guest_process.h"
#include "guest_locale.h"
#include "guest_registry.h"
#include "guest_cursor.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

static uint32_t read32(const void *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void write32(void *p, uint32_t v) { memcpy(p, &v, 4); }
static int handle_count_import(CPU *c,const GuestImport *import,uint32_t *fault) {
    if (strcmp(import->name,"SetHandleCount")) return 0;
    const uint8_t *frame=guest_memory_pointer(c->esp,8,0);
    if (!frame) { *fault=c->esp; return -1; }
    uint32_t ret=read32(frame), requested=read32(frame+4);
    /* Documented NT compatibility no-op; acknowledges the request without
     * creating handles, changing any limit, or claiming a file exists. */
    c->eax=requested; c->eip=ret; c->esp+=8u;
    return 1;
}
static int identity_import(CPU *c,const GuestImport *import,uint32_t *fault) {
    int is_thread = !strcmp(import->name,"GetCurrentThreadId");
    int is_process = !strcmp(import->name,"GetCurrentProcessId");
    if (!is_thread && !is_process) return 0;
    const void *stack=guest_memory_pointer(c->esp,4,0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack);
    if (!c->fs_base) { *fault=0; return -2; }
    uint64_t at=(uint64_t)c->fs_base+(is_process ? 0x20u : 0x24u);
    const void *identity=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,4,0) : NULL;
    if (!identity) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
    uint32_t id=read32(identity);
    if (!id) { *fault=(uint32_t)at; return -2; }
    c->eax=id; c->eip=ret; c->esp+=4u;
    return 1;
}

#define GUEST_FILETIME_LOW  0x927c8000u
#define GUEST_FILETIME_HIGH 0x01c4c66eu
#define GUEST_TICK_COUNT    1000u
#define GUEST_PERF_COUNT    1000000ULL

static int processor_feature_import(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (strcmp(import->name, "IsProcessorFeaturePresent")) return 0;
    const uint8_t *frame = guest_memory_pointer(c->esp, 8, 0);
    if (!frame) { *fault = c->esp; return -1; }
    uint32_t ret = read32(frame), feature = read32(frame + 4);
    /* The static upstream CPUID profile advertises SSE (EDX25),
     * but no SSE2 (EDX26 clear) or 3DNow. These are guest capabilities, independent of the host.
     * Unimplemented translated instructions still stop explicitly. */
    if (feature != 6u && feature != 7u && feature != 10u) return 0;
    c->eax = feature == 6u ? 1u : 0u; c->eip = ret; c->esp += 8u;
    return 1;
}

static int handle_time_import(CPU *c, const GuestImport *import, uint32_t *fault) {
    int is_filetime = !strcmp(import->name, "GetSystemTimeAsFileTime");
    int is_tick = !strcmp(import->name, "GetTickCount");
    int is_perf = !strcmp(import->name, "QueryPerformanceCounter");
    if (!is_filetime && !is_tick && !is_perf) return 0;

    if (is_tick) {
        if ((uint64_t)c->esp + 4ULL > 0x100000000ULL) { *fault = c->esp; return -1; }
        const void *stack = guest_memory_pointer(c->esp, 4, 0);
        if (!stack) { *fault = c->esp; return -1; }
        uint32_t ret = read32(stack);
        c->eax = GUEST_TICK_COUNT;
        c->eip = ret;
        c->esp += 4u;
        return 1;
    }

    if ((uint64_t)c->esp + 8ULL > 0x100000000ULL) { *fault = c->esp; return -1; }
    const uint8_t *stack = guest_memory_pointer(c->esp, 8, 0);
    if (!stack) { *fault = c->esp; return -1; }
    uint32_t ret = read32(stack);
    uint32_t target_ptr = read32(stack + 4);

    if (is_filetime) {
        if (!target_ptr || (uint64_t)target_ptr + 8ULL > 0x100000000ULL) {
            *fault = target_ptr;
            return -1;
        }
        uint8_t *out = guest_memory_pointer(target_ptr, 8, 1);
        if (!out) { *fault = target_ptr; return -1; }
        write32(out, GUEST_FILETIME_LOW);
        write32(out + 4, GUEST_FILETIME_HIGH);
        c->eip = ret;
        c->esp += 8u;
        return 1;
    }

    if (is_perf) {
        if (!target_ptr || (uint64_t)target_ptr + 8ULL > 0x100000000ULL) {
            *fault = target_ptr;
            return -1;
        }
        uint8_t *out = guest_memory_pointer(target_ptr, 8, 1);
        if (!out) { *fault = target_ptr; return -1; }
        write32(out, (uint32_t)(GUEST_PERF_COUNT & 0xFFFFFFFFu));
        write32(out + 4, (uint32_t)(GUEST_PERF_COUNT >> 32));
        c->eax = 1; /* TRUE */
        c->eip = ret;
        c->esp += 8u;
        return 1;
    }

    return 0;
}
static int tls_import(CPU *c,const GuestImport *import,GuestWindows *windows,uint32_t *fault) {
    GuestTLSOperation op; unsigned nargs;
    if (!strcmp(import->name,"TlsAlloc")) { op=GUEST_TLS_ALLOC; nargs=0; }
    else if (!strcmp(import->name,"TlsFree")) { op=GUEST_TLS_FREE; nargs=1; }
    else if (!strcmp(import->name,"TlsGetValue")) { op=GUEST_TLS_GET; nargs=1; }
    else if (!strcmp(import->name,"TlsSetValue")) { op=GUEST_TLS_SET; nargs=2; }
    else return 0;
    if (!windows) return 0;
    const uint8_t *stack=guest_memory_pointer(c->esp,4u*(nargs+1),0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack), index=nargs ? read32(stack+4) : 0;
    uint32_t value=nargs==2 ? read32(stack+8) : 0, result=0;
    /* GET clears LastError; preflight potential exhaustion reporting for all
     * calls before touching the TLS model. Success otherwise preserves it. */
    if (!c->fs_base) { *fault=0; return -2; }
    uint64_t error_at=(uint64_t)c->fs_base+0x34u;
    void *error=error_at<=UINT32_MAX ? guest_memory_pointer((uint32_t)error_at,4,1) : NULL;
    if (!error) { *fault=error_at>UINT32_MAX ? UINT32_MAX : (uint32_t)error_at; return -1; }
    int rc=guest_tls_apply(&windows->tls,c->fs_base,op,index,value,&result,fault);
    if (rc==ENOSPC && op==GUEST_TLS_ALLOC) {
        result=UINT32_MAX; write32(error,8); /* Explicit bounded-resource policy. */
    } else if (rc) return rc==EFAULT ? -1 : -2;
    else if (op==GUEST_TLS_GET) write32(error,0);
    c->eax=result; c->eip=ret; c->esp+=4u*(nargs+1);
    return 1;
}
static int critical_import(CPU *c, const GuestImport *import, GuestWindows *windows, uint32_t *fault) {
    int initialize=!strcmp(import->name,"InitializeCriticalSection");
    int enter=!strcmp(import->name,"EnterCriticalSection");
    int attempt=!strcmp(import->name,"TryEnterCriticalSection");
    int leave=!strcmp(import->name,"LeaveCriticalSection");
    int destroy=!strcmp(import->name,"DeleteCriticalSection");
    if (!windows || (!initialize && !enter && !attempt && !leave && !destroy)) return 0;
    const uint8_t *stack=guest_memory_pointer(c->esp,8,0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack), address=read32(stack+4), thread_id=0;
    if (enter || attempt || leave) {
        if (!c->fs_base) { *fault=0; return -2; }
        uint64_t at=(uint64_t)c->fs_base+0x24u;
        const void *tid=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,4,0) : NULL;
        if (!tid) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
        thread_id=read32(tid);
    }
    /* Validate memory before native state lookup so an unmapped section is
     * diagnosed consistently, even if it was never initialized. */
    if (!address || !guest_memory_pointer(address,GUEST_CRITICAL_BYTES,1)) {
        *fault=address; return -1;
    }
    int rc;
    if (initialize) rc=guest_critical_create(&windows->critical,address);
    else if (enter || attempt) rc=guest_critical_acquire(&windows->critical,address,thread_id);
    else if (leave) rc=guest_critical_release(&windows->critical,address,thread_id);
    else rc=guest_critical_delete(&windows->critical,address);
    if (rc && !(attempt && rc==EBUSY)) { *fault=address; return rc==EFAULT ? -1 : -2; }
    if (attempt) c->eax=!rc; /* The other four APIs return void. */
    c->eip=ret; c->esp+=8u;
    return 1;
}
static int heap_import(CPU *c, const GuestImport *import, GuestWindows *windows, uint32_t *fault) {
    unsigned nargs=0;
    int create=!strcmp(import->name,"HeapCreate"), alloc=!strcmp(import->name,"HeapAlloc");
    int release=!strcmp(import->name,"HeapFree"), size=!strcmp(import->name,"HeapSize");
    int destroy=!strcmp(import->name,"HeapDestroy"), realloc=!strcmp(import->name,"HeapReAlloc");
    if (realloc) nargs=4;
    else if (create || alloc || release || size) nargs=3;
    else if (destroy) nargs=1;
    if (!nargs || !windows) return 0;
    const uint8_t *stack=guest_memory_pointer(c->esp,4u*(nargs+1),0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack), a=read32(stack+4), b=nargs>1 ? read32(stack+8) : 0;
    uint32_t d=nargs>2 ? read32(stack+12) : 0, e=nargs>3 ? read32(stack+16) : 0, result=0;
    /* Exception-generating/executable heaps require capabilities we do not
     * provide. Stop before altering state rather than silently drop flags. */
    if ((create && (a & ~1u)) || (alloc && (b & ~9u)) ||
        ((release || size) && (b & ~1u)) ||
        (realloc && (b & ~(1u | 8u | 0x10u)))) return 0;
    void *error = NULL;
    if (!alloc && !size) {
        if (!c->fs_base) { *fault=0; return -2; }
        uint64_t error_at=(uint64_t)c->fs_base+0x34u;
        error=error_at<=UINT32_MAX ? guest_memory_pointer((uint32_t)error_at,4,1) : NULL;
        if (!error) { *fault=error_at>UINT32_MAX ? UINT32_MAX : (uint32_t)error_at; return -1; }
    }
    int rc;
    if (create) {
        uint64_t maximum=((uint64_t)d+GUEST_MEMORY_GRANULE-1)&~(uint64_t)(GUEST_MEMORY_GRANULE-1);
        rc=maximum>UINT32_MAX ? ENOMEM : guest_heap_create(&windows->heaps,b,(uint32_t)maximum,&result);
        if (rc) write32(error,rc==EINVAL ? 87 : 8);
    } else if (alloc) {
        rc=guest_heap_alloc(&windows->heaps,a,d,!!(b&8u),&result);
        if (rc) result=0; /* HeapAlloc never sets LastError. */
    } else if (realloc) {
        rc=guest_heap_realloc(&windows->heaps,a,b,d,e,&result);
        if (rc) { result=0; write32(error,rc==EINVAL ? 87 : 8); }
    } else if (release) {
        rc=guest_heap_free(&windows->heaps,a,d); result=!rc;
        if (rc) write32(error,87);
    } else if (size) {
        rc=guest_heap_size(&windows->heaps,a,d,&result);
        if (rc) result=UINT32_MAX; /* HeapSize, like HeapAlloc, preserves LastError. */
    } else {
        rc=guest_heap_destroy(&windows->heaps,a); result=!rc;
        if (rc) write32(error,87);
    }
    c->eax=result; c->eip=ret; c->esp+=4u*(nargs+1);
    return 1;
}

static uint8_t utf16_to_cp1252_special(uint16_t w) {
    switch (w) {
        case 0x0081: return 0x81;
        case 0x008D: return 0x8D;
        case 0x008F: return 0x8F;
        case 0x0090: return 0x90;
        case 0x009D: return 0x9D;
        case 0x20AC: return 0x80; /* Euro Sign */
        case 0x201A: return 0x82; /* Single Low-9 Quotation Mark */
        case 0x0192: return 0x83; /* Latin Small Letter F With Hook */
        case 0x201E: return 0x84; /* Double Low-9 Quotation Mark */
        case 0x2026: return 0x85; /* Horizontal Ellipsis */
        case 0x2020: return 0x86; /* Dagger */
        case 0x2021: return 0x87; /* Double Dagger */
        case 0x02C6: return 0x88; /* Modifier Letter Circumflex Accent */
        case 0x2030: return 0x89; /* Per Mille Sign */
        case 0x0160: return 0x8A; /* Latin Capital Letter S With Caron */
        case 0x2039: return 0x8B; /* Single Left-Pointing Angle Quotation Mark */
        case 0x0152: return 0x8C; /* Latin Capital Ligature OE */
        case 0x017D: return 0x8E; /* Latin Capital Letter Z With Caron */
        case 0x2018: return 0x91; /* Left Single Quotation Mark */
        case 0x2019: return 0x92; /* Right Single Quotation Mark */
        case 0x201C: return 0x93; /* Left Double Quotation Mark */
        case 0x201D: return 0x94; /* Right Double Quotation Mark */
        case 0x2022: return 0x95; /* Bullet */
        case 0x2013: return 0x96; /* En Dash */
        case 0x2014: return 0x97; /* Em Dash */
        case 0x02DC: return 0x98; /* Small Tilde */
        case 0x2122: return 0x99; /* Trade Mark Sign */
        case 0x0161: return 0x9A; /* Latin Small Letter S With Caron */
        case 0x203A: return 0x9B; /* Single Right-Pointing Angle Quotation Mark */
        case 0x0153: return 0x9C; /* Latin Small Ligature OE */
        case 0x017E: return 0x9E; /* Latin Small Letter Z With Caron */
        case 0x0178: return 0x9F; /* Latin Capital Letter Y With Diaeresis */
        default:     return 0;
    }
}

static int set_guest_last_error(CPU *c, uint32_t error_code, uint32_t *fault) {
    if (!c->fs_base) {
        *fault = 0;
        return -2; /* GUEST_STOP_API_STATE */
    }
    uint64_t teb_addr = (uint64_t)c->fs_base + 0x34u;
    if (teb_addr > UINT32_MAX || teb_addr + 4u > 0x100000000ULL) {
        *fault = (teb_addr > UINT32_MAX) ? UINT32_MAX : (uint32_t)teb_addr;
        return -1;
    }
    void *error_ptr = guest_memory_pointer((uint32_t)teb_addr, 4, 1);
    if (!error_ptr) {
        *fault = (uint32_t)teb_addr;
        return -1;
    }
    write32(error_ptr, error_code);
    return 0;
}

static int window_query_import(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (strcmp(import->name, "GetWindowRect") && strcmp(import->name, "GetClientRect")) return 0;
    const uint8_t *frame = guest_memory_pointer(c->esp, 12, 0);
    if (!frame) { *fault = c->esp; return -1; }
    uint32_t ret = read32(frame), window = read32(frame + 4);
    if (window) return 0; /* No guest HWND has been created or bound yet. */
    /* Native Windows rejects HWND=NULL before touching lpRect. Preserve that
     * failure instead of inventing successful dimensions for a missing window. */
    int rc = set_guest_last_error(c, 1400u, fault);
    if (rc) return rc;
    c->eax = 0; c->eip = ret; c->esp += 12u;
    return 1;
}

int guest_user32_get_system_metrics(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (!c || !import || !import->name || !fault) return 0;
    if (strcmp(import->name, "GetSystemMetrics") != 0) return 0;
    if (!import->library || strcasecmp(import->library, "USER32.dll") != 0) return 0;

    const uint8_t *frame = guest_memory_pointer(c->esp, 8, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip = read32(frame);
    uint32_t metric = read32(frame + 4);

    /* Explicit guest input policy: touch/primary mouse maps to left button.
     * No host desktop dimensions or successful unknown metric fallback. */
    if (metric != 23u) return 0; /* SM_SWAPBUTTON */
    c->eax = 0;
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

static int handle_get_module_file_name_a(CPU *c, const GuestImport *import,
                                         GuestWindows *windows, uint32_t *fault) {
    if (strcmp(import->name, "GetModuleFileNameA") != 0) return 0;
    if (!windows) return 0;

    uint64_t esp_sum = (uint64_t)c->esp + 16ULL;
    if (esp_sum > 0x100000000ULL) {
        *fault = c->esp;
        return -1;
    }
    const uint8_t *stack = guest_memory_pointer(c->esp, 16ULL, 0);
    if (!stack) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip     = read32(stack);
    uint32_t hModule    = read32(stack + 4);
    uint32_t lpFilename = read32(stack + 8);
    uint32_t nSize      = read32(stack + 12);

    if (hModule != 0 && hModule != windows->image_base) {
        int rc = set_guest_last_error(c, 126, fault); /* ERROR_MOD_NOT_FOUND */
        if (rc) return rc;
        c->eax = 0;
        c->eip = ret_ip;
        c->esp += 16u;
        return 1;
    }

    if (nSize == 0) {
        c->eax = 0;
        c->eip = ret_ip;
        c->esp += 16u;
        return 1;
    }

    uint64_t buf_end = (uint64_t)lpFilename + (uint64_t)nSize;
    if (buf_end > 0x100000000ULL) {
        *fault = lpFilename;
        return -1;
    }
    void *dest = guest_memory_pointer(lpFilename, (uint64_t)nSize, 1);
    if (!dest) {
        *fault = lpFilename;
        return -1;
    }

    static const char canonical_path[] = "C:\\NFSU2\\SPEED2.EXE";
    const uint32_t full_len = (uint32_t)(sizeof(canonical_path) - 1); /* 19 */

    if (nSize > full_len) {
        memcpy(dest, canonical_path, full_len + 1);
        c->eax = full_len;
    } else {
        memcpy(dest, canonical_path, nSize);
        int rc = set_guest_last_error(c, 122, fault); /* ERROR_INSUFFICIENT_BUFFER */
        if (rc) return rc;
        c->eax = nSize;
    }

    c->eip = ret_ip;
    c->esp += 16u;
    return 1;
}

static int handle_set_unhandled_exception_filter(CPU *c, const GuestImport *import,
                                                GuestWindows *windows, uint32_t *fault) {
    if (strcmp(import->name, "SetUnhandledExceptionFilter") != 0) return 0;

    uint64_t esp_sum = (uint64_t)c->esp + 8ULL;
    if (esp_sum > 0x100000000ULL) {
        *fault = c->esp;
        return -1;
    }
    const uint8_t *stack = guest_memory_pointer(c->esp, 8, 0);
    if (!stack) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip = read32(stack);
    uint32_t new_filter = read32(stack + 4);
    uint32_t prev_filter = 0;

    if (windows) {
        prev_filter = windows->unhandled_exception_filter;
        windows->unhandled_exception_filter = new_filter;
    } else {
        static uint32_t s_fallback_filter = 0;
        prev_filter = s_fallback_filter;
        s_fallback_filter = new_filter;
    }

    c->eax = prev_filter;
    c->eip = ret_ip;
    c->esp += 8u;
    return 1;
}

static int widechar_import(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (strcmp(import->name, "WideCharToMultiByte")) return 0;

    if ((uint64_t)c->esp + 36ULL > 0x100000000ULL) {
        *fault = c->esp;
        return -1;
    }
    const uint8_t *frame = guest_memory_pointer(c->esp, 36, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }

    uint32_t ret_ip               = read32(frame);
    uint32_t code_page            = read32(frame + 4);
    uint32_t dw_flags             = read32(frame + 8);
    uint32_t lp_wide_char_str     = read32(frame + 12);
    int32_t  cch_wide_char        = (int32_t)read32(frame + 16);
    uint32_t lp_multi_byte_str    = read32(frame + 20);
    int32_t  cb_multi_byte        = (int32_t)read32(frame + 24);
    uint32_t lp_default_char      = read32(frame + 28);
    uint32_t lp_used_default_char = read32(frame + 32);
    (void)dw_flags;

    if (cch_wide_char == 0 || cb_multi_byte < 0 || !lp_wide_char_str ||
        (cb_multi_byte > 0 && !lp_multi_byte_str)) {
        int rc = set_guest_last_error(c, 87, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 36u;
        return 1;
    }

    int is_utf8 = (code_page == 65001);
    if (!is_utf8 && code_page != 0 && code_page != 1252 && code_page != 1 && code_page != 3) {
        int rc = set_guest_last_error(c, 87, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 36u;
        return 1;
    }

    if (is_utf8 && (lp_default_char != 0 || lp_used_default_char != 0)) {
        int rc = set_guest_last_error(c, 87, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 36u;
        return 1;
    }

    uint8_t default_char = '?';
    if (lp_default_char) {
        const void *dc_ptr = guest_memory_pointer(lp_default_char, 1, 0);
        if (!dc_ptr) {
            *fault = lp_default_char;
            return -1;
        }
        default_char = *(const uint8_t *)dc_ptr;
    }

    if (lp_used_default_char) {
        if ((uint64_t)lp_used_default_char + 4ULL > 0x100000000ULL) {
            *fault = lp_used_default_char;
            return -1;
        }
        void *ud_ptr = guest_memory_pointer(lp_used_default_char, 4, 1);
        if (!ud_ptr) {
            *fault = lp_used_default_char;
            return -1;
        }
        write32(ud_ptr, 0);
    }

    uint32_t src_len = 0;
    if (cch_wide_char < 0) {
        for (uint32_t i = 0; ; i++) {
            uint64_t at = (uint64_t)lp_wide_char_str + (uint64_t)i * 2ULL;
            if (at + 2ULL > 0x100000000ULL) {
                *fault = (at > UINT32_MAX) ? UINT32_MAX : (uint32_t)at;
                return -1;
            }
            const void *p = guest_memory_pointer((uint32_t)at, 2, 0);
            if (!p) {
                *fault = (uint32_t)at;
                return -1;
            }
            uint16_t w;
            memcpy(&w, p, 2);
            if (w == 0) {
                src_len = i + 1u;
                break;
            }
            if (i >= 0x100000u) {
                *fault = (uint32_t)at;
                return -1;
            }
        }
    } else {
        src_len = (uint32_t)cch_wide_char;
        uint64_t src_bytes = (uint64_t)src_len * 2ULL;
        if ((uint64_t)lp_wide_char_str + src_bytes > 0x100000000ULL) {
            *fault = lp_wide_char_str;
            return -1;
        }
        if (!guest_memory_pointer(lp_wide_char_str, src_bytes, 0)) {
            *fault = lp_wide_char_str;
            return -1;
        }
    }

    uint32_t needed_bytes = 0;
    if (!is_utf8) {
        needed_bytes = src_len;
    } else {
        for (uint32_t i = 0; i < src_len; i++) {
            const void *p = guest_memory_pointer(lp_wide_char_str + 2u * i, 2, 0);
            uint16_t w;
            memcpy(&w, p, 2);
            if (w < 0x80u) {
                needed_bytes += 1u;
            } else if (w < 0x800u) {
                needed_bytes += 2u;
            } else if (w >= 0xD800u && w <= 0xDBFFu && (i + 1u) < src_len) {
                const void *p2 = guest_memory_pointer(lp_wide_char_str + 2u * (i + 1u), 2, 0);
                uint16_t w2;
                memcpy(&w2, p2, 2);
                if (w2 >= 0xDC00u && w2 <= 0xDFFFu) {
                    needed_bytes += 4u;
                    i++;
                } else {
                    needed_bytes += 3u;
                }
            } else {
                needed_bytes += 3u;
            }
        }
    }

    if (cb_multi_byte == 0) {
        c->eax = needed_bytes;
        c->eip = ret_ip;
        c->esp += 36u;
        return 1;
    }

    uint64_t dst_bytes = (uint64_t)cb_multi_byte;
    if ((uint64_t)lp_multi_byte_str + dst_bytes > 0x100000000ULL) {
        *fault = lp_multi_byte_str;
        return -1;
    }
    void *dst_ptr = guest_memory_pointer(lp_multi_byte_str, dst_bytes, 1);
    if (!dst_ptr) {
        *fault = lp_multi_byte_str;
        return -1;
    }

    if ((uint32_t)cb_multi_byte < needed_bytes) {
        int rc = set_guest_last_error(c, 122, fault);
        if (rc) return rc;
        c->eax = 0;
        c->eip = ret_ip;
        c->esp += 36u;
        return 1;
    }

    int used_default = 0;
    uint8_t stack_buf[1024];
    uint8_t *staged = (needed_bytes <= sizeof(stack_buf)) ? stack_buf : (uint8_t *)malloc(needed_bytes);
    if (!staged) {
        *fault = lp_multi_byte_str;
        return -1;
    }

    if (!is_utf8) {
        for (uint32_t i = 0; i < src_len; i++) {
            const void *p = guest_memory_pointer(lp_wide_char_str + 2u * i, 2, 0);
            uint16_t w;
            memcpy(&w, p, 2);
            if (w <= 0x7Fu) {
                staged[i] = (uint8_t)w;
            } else if (w >= 0xA0u && w <= 0xFFu) {
                staged[i] = (uint8_t)w;
            } else {
                uint8_t sp = w == 0x0191u && !(dw_flags & 0x400u) ? 0x83u : utf16_to_cp1252_special(w);
                if (sp) {
                    staged[i] = sp;
                } else {
                    staged[i] = default_char;
                    used_default = 1;
                }
            }
        }
    } else {
        uint32_t out_idx = 0;
        for (uint32_t i = 0; i < src_len; i++) {
            const void *p = guest_memory_pointer(lp_wide_char_str + 2u * i, 2, 0);
            uint16_t w;
            memcpy(&w, p, 2);
            if (w < 0x80u) {
                staged[out_idx++] = (uint8_t)w;
            } else if (w < 0x800u) {
                staged[out_idx++] = (uint8_t)(0xC0u | (w >> 6));
                staged[out_idx++] = (uint8_t)(0x80u | (w & 0x3Fu));
            } else if (w >= 0xD800u && w <= 0xDBFFu && (i + 1u) < src_len) {
                const void *p2 = guest_memory_pointer(lp_wide_char_str + 2u * (i + 1u), 2, 0);
                uint16_t w2;
                memcpy(&w2, p2, 2);
                if (w2 >= 0xDC00u && w2 <= 0xDFFFu) {
                    uint32_t cp = 0x10000u + (((uint32_t)(w & 0x3FFu) << 10) | (uint32_t)(w2 & 0x3FFu));
                    staged[out_idx++] = (uint8_t)(0xF0u | (cp >> 18));
                    staged[out_idx++] = (uint8_t)(0x80u | ((cp >> 12) & 0x3Fu));
                    staged[out_idx++] = (uint8_t)(0x80u | ((cp >> 6) & 0x3Fu));
                    staged[out_idx++] = (uint8_t)(0x80u | (cp & 0x3Fu));
                    i++;
                } else {
                    staged[out_idx++] = (uint8_t)(0xE0u | (w >> 12));
                    staged[out_idx++] = (uint8_t)(0x80u | ((w >> 6) & 0x3Fu));
                    staged[out_idx++] = (uint8_t)(0x80u | (w & 0x3Fu));
                }
            } else {
                staged[out_idx++] = (uint8_t)(0xE0u | (w >> 12));
                staged[out_idx++] = (uint8_t)(0x80u | ((w >> 6) & 0x3Fu));
                staged[out_idx++] = (uint8_t)(0x80u | (w & 0x3Fu));
            }
        }
    }

    memcpy(dst_ptr, staged, needed_bytes);
    if (staged != stack_buf) free(staged);

    if (lp_used_default_char) {
        void *ud_ptr = guest_memory_pointer(lp_used_default_char, 4, 1);
        if (ud_ptr) write32(ud_ptr, used_default ? 1u : 0u);
    }

    c->eax = needed_bytes;
    c->eip = ret_ip;
    c->esp += 36u;
    return 1;
}

static int multibyte_import(CPU *c, const GuestImport *import, uint32_t *fault) {
    if (strcmp(import->name, "MultiByteToWideChar")) return 0;
    if ((uint64_t)c->esp + 28ULL > 0x100000000ULL) {
        *fault = c->esp;
        return -1;
    }
    const uint8_t *frame = guest_memory_pointer(c->esp, 28, 0);
    if (!frame) {
        *fault = c->esp;
        return -1;
    }
    uint32_t ret_ip         = read32(frame);
    uint32_t code_page      = read32(frame + 4);
    uint32_t dw_flags       = read32(frame + 8);
    uint32_t lp_multi_byte  = read32(frame + 12);
    int32_t  cb_multi_byte  = (int32_t)read32(frame + 16);
    uint32_t lp_wide_char   = read32(frame + 20);
    int32_t  cch_wide_char  = (int32_t)read32(frame + 24);
    (void)dw_flags;

    if (cb_multi_byte == 0 || cch_wide_char < 0 || !lp_multi_byte ||
        (cch_wide_char > 0 && !lp_wide_char)) {
        int rc = set_guest_last_error(c, 87, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 28u;
        return 1;
    }

    int is_utf8 = (code_page == 65001);
    if (!is_utf8 && code_page != 0 && code_page != 1252 && code_page != 1 && code_page != 3) {
        int rc = set_guest_last_error(c, 87, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 28u;
        return 1;
    }

    uint32_t src_len = 0;
    if (cb_multi_byte < 0) {
        for (uint32_t i = 0; ; i++) {
            uint64_t at = (uint64_t)lp_multi_byte + i;
            if (at >= 0x100000000ULL) {
                *fault = (uint32_t)at; return -1;
            }
            const uint8_t *p = guest_memory_pointer((uint32_t)at, 1, 0);
            if (!p) { *fault = (uint32_t)at; return -1; }
            if (*p == 0) { src_len = i + 1u; break; }
            if (i >= 0x100000u) { *fault = (uint32_t)at; return -1; }
        }
    } else {
        src_len = (uint32_t)cb_multi_byte;
        if ((uint64_t)lp_multi_byte + src_len > 0x100000000ULL ||
            !guest_memory_pointer(lp_multi_byte, src_len, 0)) {
            *fault = lp_multi_byte; return -1;
        }
    }

    uint32_t needed_chars = 0;
    if (!is_utf8) {
        needed_chars = src_len;
    } else {
        const uint8_t *src_buf = guest_memory_pointer(lp_multi_byte, src_len, 0);
        uint32_t idx = 0;
        while (idx < src_len) {
            uint8_t b = src_buf[idx];
            if (b < 0x80) { needed_chars++; idx++; }
            else if ((b & 0xE0) == 0xC0) { needed_chars++; idx += (idx + 1 < src_len) ? 2 : 1; }
            else if ((b & 0xF0) == 0xE0) { needed_chars++; idx += (idx + 2 < src_len) ? 3 : 1; }
            else if ((b & 0xF8) == 0xF0) { needed_chars += 2; idx += (idx + 3 < src_len) ? 4 : 1; }
            else { needed_chars++; idx++; }
        }
    }

    if (cch_wide_char == 0) {
        c->eax = needed_chars;
        c->eip = ret_ip;
        c->esp += 28u;
        return 1;
    }

    if ((uint32_t)cch_wide_char < needed_chars) {
        int rc = set_guest_last_error(c, 122, fault);
        if (rc) return rc;
        c->eax = 0; c->eip = ret_ip; c->esp += 28u;
        return 1;
    }

    uint64_t dst_bytes = (uint64_t)cch_wide_char * 2ULL;
    if ((uint64_t)lp_wide_char + dst_bytes > 0x100000000ULL ||
        !guest_memory_pointer(lp_wide_char, dst_bytes, 1)) {
        *fault = lp_wide_char; return -1;
    }

    const uint8_t *src = guest_memory_pointer(lp_multi_byte, src_len, 0);
    uint16_t *dst = (uint16_t *)guest_memory_pointer(lp_wide_char, (uint64_t)needed_chars * 2ULL, 1);
    if (!is_utf8) {
        for (uint32_t i = 0; i < src_len; i++) {
            uint8_t b = src[i];
            if (b >= 0x80 && b <= 0x9F) {
                static const uint16_t cp1252_to_unicode[32] = {
                    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
                    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
                    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
                    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178
                };
                dst[i] = cp1252_to_unicode[b - 0x80];
            } else {
                dst[i] = (uint16_t)b;
            }
        }
    } else {
        uint32_t in_i = 0, out_i = 0;
        while (in_i < src_len && out_i < needed_chars) {
            uint8_t b = src[in_i];
            if (b < 0x80) { dst[out_i++] = b; in_i++; }
            else if ((b & 0xE0) == 0xC0 && in_i + 1 < src_len) {
                dst[out_i++] = (uint16_t)(((b & 0x1F) << 6) | (src[in_i + 1] & 0x3F));
                in_i += 2;
            } else if ((b & 0xF0) == 0xE0 && in_i + 2 < src_len) {
                dst[out_i++] = (uint16_t)(((b & 0x0F) << 12) | ((src[in_i + 1] & 0x3F) << 6) | (src[in_i + 2] & 0x3F));
                in_i += 3;
            } else if ((b & 0xF8) == 0xF0 && in_i + 3 < src_len) {
                uint32_t cp = (((b & 0x07) << 18) | ((src[in_i + 1] & 0x3F) << 12) |
                               ((src[in_i + 2] & 0x3F) << 6) | (src[in_i + 3] & 0x3F)) - 0x10000;
                dst[out_i++] = (uint16_t)(0xD800 + (cp >> 10));
                dst[out_i++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
                in_i += 4;
            } else {
                dst[out_i++] = (uint16_t)b; in_i++;
            }
        }
    }
    c->eax = needed_chars;
    c->eip = ret_ip;
    c->esp += 28u;
    return 1;
}

int guest_windows_import(CPU *c, const GuestImport *import, void *context,
                         uint32_t *fault) {
    if (!c || !import || !import->name || !import->library || !fault) return 0;
    if (!strcasecmp(import->library, "ADVAPI32.dll"))
        return guest_registry_import(c, import, fault);
    if (!strcasecmp(import->library, "USER32.dll")) {
        int handled = window_query_import(c, import, fault);
        if (handled) return handled;
        handled = guest_user32_get_system_metrics(c, import, fault);
        if (handled) return handled;
        handled = guest_user32_get_cursor_pos(c, import, fault);
        if (handled) return handled;
        handled = guest_user32_set_cursor_pos(c, import, fault);
        if (handled) return handled;
        handled = guest_user32_show_cursor(c, import, fault);
        if (handled) return handled;
        return 0;
    }
    int version = !strcmp(import->name, "GetVersionExA");
    int module = !strcmp(import->name, "GetModuleHandleA");
    if (strcasecmp(import->library, "KERNEL32.dll")) return 0;
    if (!version && !module) {
        int handled=guest_startup_import(c,import,fault);
        if (handled) return handled;
        handled=guest_error_import(c,import,fault);
        if (handled) return handled;
        handled=guest_stdio_import(c,import,fault);
        if (handled) return handled;
        handled=handle_count_import(c,import,fault);
        if (handled) return handled;
        handled=identity_import(c,import,fault);
        if (handled) return handled;
        handled=handle_time_import(c,import,fault);
        if (handled) return handled;
        handled=processor_feature_import(c,import,fault);
        if (handled) return handled;
        handled=guest_process_import(c,import,context ? &((GuestWindows *)context)->process : NULL,fault);
        if (handled) return handled;
        handled=tls_import(c,import,context,fault);
        if (handled) return handled;
        handled=critical_import(c,import,context,fault);
        if (handled) return handled;
        handled=handle_get_module_file_name_a(c,import,(GuestWindows *)context,fault);
        if (handled) return handled;
        handled=handle_set_unhandled_exception_filter(c,import,(GuestWindows *)context,fault);
        if (handled) return handled;
        handled=widechar_import(c,import,fault);
        if (handled) return handled;
        handled=multibyte_import(c,import,fault);
        if (handled) return handled;
        handled=guest_locale_import(c,import,fault);
        if (handled) return handled;
        return heap_import(c,import,context,fault);
    }
    if (module && !context) return 0;
    /* Validate the return and argument together: wrapped x86 stack ranges are
     * rejected, and a malformed API never partly consumes the guest stack. */
    const uint8_t *stack = guest_memory_pointer(c->esp, 8, 0);
    if (!stack) { *fault = c->esp; return -1; }
    uint32_t return_ip = read32(stack), address = read32(stack + 4);
    if (module) {
        char name[261] = {0}; int terminated=1;
        if (address) {
            unsigned i;
            for (i=0; i<260; i++) {
                uint64_t at=(uint64_t)address+i;
                const char *p=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,1,0) : NULL;
                if (!p) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
                name[i]=*p;
                if (!name[i]) break;
            }
            if (i==260) terminated=0; /* Overlong input cannot identify our module. */
        }
        uint32_t value=0;
        if (terminated && (!address || !strcasecmp(name,"SPEED2.EXE")))
            value=((GuestWindows *)context)->image_base;
        if (!value) {
            if (!c->fs_base) { *fault=0; return -2; }
            uint64_t at=(uint64_t)c->fs_base+0x34u;
            void *error=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,4,1) : NULL;
            if (!error) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
            write32(error,126); /* ERROR_MOD_NOT_FOUND */
        }
        c->eax=value; c->eip=return_ip; c->esp+=8u;
        return 1;
    }
    if (!address) { *fault=0; return -1; }
    const void *size_pointer = guest_memory_pointer(address, 4, 0);
    if (!size_pointer) { *fault = address; return -1; }
    uint32_t size = read32(size_pointer), value;
    if (size != 148 && size != 156) {
        if (!c->fs_base) { *fault=0; return -2; }
        uint64_t error_address = (uint64_t)c->fs_base + 0x34u;
        void *error = error_address <= UINT32_MAX ?
            guest_memory_pointer((uint32_t)error_address, 4, 1) : NULL;
        if (!error) { *fault = error_address>UINT32_MAX ? UINT32_MAX : (uint32_t)error_address; return -1; }
        write32(error, 122); /* ERROR_INSUFFICIENT_BUFFER */
        value = 0;
    } else {
        uint8_t *output = guest_memory_pointer(address, size, 1);
        if (!output) { *fault = address; return -1; }
        /* Stage output to support unaligned and aliased guest buffers safely. */
        uint8_t version[156] = {0};
        write32(version, size);
        write32(version + 4, 5);
        write32(version + 8, 1);
        write32(version + 12, 2600);
        write32(version + 16, 2); /* VER_PLATFORM_WIN32_NT */
        if (size == 156) { version[153] = 1; version[154] = 1; }
        memcpy(output, version, size);
        value = 1; /* Success preserves the thread's existing LastError. */
    }
    c->eax = value;
    c->eip = return_ip;
    c->esp += 8u;
    return 1;
}
int guest_windows_cleanup(GuestWindows *windows) {
    if (!windows) return EINVAL;
    windows->unhandled_exception_filter = 0;
    guest_process_cleanup(&windows->process);
    int rc=guest_critical_cleanup(&windows->critical);
    if (!rc) guest_tls_cleanup(&windows->tls);
    return rc;
}
