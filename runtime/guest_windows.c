#include "guest_windows.h"
#include "guest_memory.h"
#include "guest_startup.h"
#include "guest_error.h"
#include "guest_stdio.h"
#include "guest_process.h"
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
    if (strcmp(import->name,"GetCurrentThreadId")) return 0;
    const void *stack=guest_memory_pointer(c->esp,4,0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack);
    uint64_t at=(uint64_t)c->fs_base+0x24u;
    const void *identity=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,4,0) : NULL;
    if (!identity) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
    uint32_t id=read32(identity);
    if (!id) { *fault=(uint32_t)at; return -2; }
    c->eax=id; c->eip=ret; c->esp+=4u;
    return 1;
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
    int destroy=!strcmp(import->name,"HeapDestroy");
    if (create || alloc || release || size) nargs=3;
    else if (destroy) nargs=1;
    if (!nargs || !windows) return 0;
    const uint8_t *stack=guest_memory_pointer(c->esp,4u*(nargs+1),0);
    if (!stack) { *fault=c->esp; return -1; }
    uint32_t ret=read32(stack), a=read32(stack+4), b=nargs>1 ? read32(stack+8) : 0;
    uint32_t d=nargs>2 ? read32(stack+12) : 0, result=0;
    /* Exception-generating/executable heaps require capabilities we do not
     * provide. Stop before altering state rather than silently drop flags. */
    if ((create && (a & ~1u)) || (alloc && (b & ~9u)) ||
        ((release || size) && (b & ~1u))) return 0;
    uint64_t error_at=(uint64_t)c->fs_base+0x34u;
    void *error=error_at<=UINT32_MAX ? guest_memory_pointer((uint32_t)error_at,4,1) : NULL;
    if (!alloc && !size && !error) { *fault=error_at>UINT32_MAX ? UINT32_MAX : (uint32_t)error_at; return -1; }
    int rc;
    if (create) {
        uint64_t maximum=((uint64_t)d+GUEST_MEMORY_GRANULE-1)&~(uint64_t)(GUEST_MEMORY_GRANULE-1);
        rc=maximum>UINT32_MAX ? ENOMEM : guest_heap_create(&windows->heaps,b,(uint32_t)maximum,&result);
        if (rc) write32(error,rc==EINVAL ? 87 : 8);
    } else if (alloc) {
        rc=guest_heap_alloc(&windows->heaps,a,d,!!(b&8u),&result);
        if (rc) result=0; /* HeapAlloc never sets LastError. */
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

int guest_windows_import(CPU *c, const GuestImport *import, void *context,
                         uint32_t *fault) {
    if (!c || !import || !import->name || !import->library || !fault) return 0;
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
        handled=guest_process_import(c,import,context ? &((GuestWindows *)context)->process : NULL,fault);
        if (handled) return handled;
        handled=tls_import(c,import,context,fault);
        if (handled) return handled;
        handled=critical_import(c,import,context,fault);
        return handled ? handled : heap_import(c,import,context,fault);
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
            uint64_t at=(uint64_t)c->fs_base+0x34u;
            void *error=at<=UINT32_MAX ? guest_memory_pointer((uint32_t)at,4,1) : NULL;
            if (!error) { *fault=at>UINT32_MAX ? UINT32_MAX : (uint32_t)at; return -1; }
            write32(error,126); /* ERROR_MOD_NOT_FOUND */
        }
        c->eax=value; c->eip=return_ip; c->esp+=8u;
        return 1;
    }
    const void *size_pointer = guest_memory_pointer(address, 4, 0);
    if (!size_pointer) { *fault = address; return -1; }
    uint32_t size = read32(size_pointer), value;
    if (size != 148 && size != 156) {
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
    guest_process_cleanup(&windows->process);
    int rc=guest_critical_cleanup(&windows->critical);
    if (!rc) guest_tls_cleanup(&windows->tls);
    return rc;
}
