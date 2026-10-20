#include "guest_windows.h"
#include "guest_memory.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL Windows bridge line %d\n",__LINE__); return 1; } } while(0)
#define STACK 0x10000u
#define BUFFER 0x20001u
#define TEB 0x30000u
static void put(uint32_t a, uint32_t v) { memcpy(g_mem+a,&v,4); }
static uint32_t get(uint32_t a) { uint32_t v; memcpy(&v,g_mem+a,4); return v; }
static CPU setup(uint32_t size) {
    CPU c = {0}; c.esp=STACK; c.fs_base=TEB;
    c.ebx=0xbad12345u; c.ecx=0xabcdef12u;
    put(STACK,0x401005u); put(STACK+4,BUFFER); put(BUFFER,size); put(TEB+0x34,999);
    return c;
}
static void caller(CPU *c) {
    guest_execution_step(c,0x401000u);
    guest_execution_call(c,GUEST_IMPORT_BASE);
    guest_execution_step(c,0x401005u);
}
static int tls_contract(void) {
    GuestWindows windows={0}; uint32_t fault=0;
    GuestImport api={0,"KERNEL32.dll","TlsAlloc"};
    put(TEB+0x24,1); put(TEB+0x2c,0x12345678u);
    CPU c=setup(0), expected=c;
    eflags_set(&c,0xcd5u); expected=c;
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==0);
    expected.eax=0; expected.esp+=4; expected.eip=0x401005;
    CHECK(!memcmp(&c,&expected,sizeof c) && get(TEB+0x34)==999);
    CHECK(guest_tls_count(&windows.tls)==1 && get(TEB+0x2c)==0x12345678u);
    api.name="TlsSetValue"; c=setup(0); put(STACK+4,0); put(STACK+8,UINT32_MAX);
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==1 && c.esp==STACK+12);
    CHECK(get(TEB+GUEST_TLS_OFFSET)==UINT32_MAX && get(TEB+0x34)==999);
    api.name="TlsGetValue"; c=setup(0); put(STACK+4,0);
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==UINT32_MAX && c.esp==STACK+8);
    CHECK(!get(TEB+0x34));
    put(TEB+GUEST_TLS_OFFSET,0); c=setup(0); put(STACK+4,0);
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && !c.eax && !get(TEB+0x34));
    c=setup(0); put(STACK+4,64); expected=c; GuestTLSSet snapshot=windows.tls;
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==-2 && !memcmp(&c,&expected,sizeof c));
    CHECK(!memcmp(&snapshot,&windows.tls,sizeof snapshot) && get(TEB+0x34)==999);
    api.name="TlsAlloc";
    for (unsigned i=1;i<64;i++) {
        c=setup(0); CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==i);
    }
    c=setup(0); snapshot=windows.tls;
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==UINT32_MAX && get(TEB+0x34)==8);
    CHECK(!memcmp(&snapshot,&windows.tls,sizeof snapshot));
    api.name="TlsFree"; c=setup(0); put(STACK+4,0);
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && c.eax==1 && get(TEB+0x34)==999);
    api.name="TlsAlloc"; c=setup(0);
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==1 && !c.eax && !get(TEB+GUEST_TLS_OFFSET));
    api.name="TlsSetValue"; c=setup(0); c.esp=UINT32_MAX-3u; expected=c; snapshot=windows.tls;
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==-1 && !memcmp(&c,&expected,sizeof c));
    CHECK(!memcmp(&snapshot,&windows.tls,sizeof snapshot));
    c=setup(0); c.fs_base=UINT32_MAX-0x10u; expected=c;
    CHECK(guest_windows_import(&c,&api,&windows,&fault)==-1 && fault==UINT32_MAX);
    CHECK(!memcmp(&c,&expected,sizeof c) && !memcmp(&snapshot,&windows.tls,sizeof snapshot));
    CHECK(!guest_windows_cleanup(&windows) && !guest_tls_count(&windows.tls));
    api.name="GetCurrentThreadId"; c=setup(0); eflags_set(&c,0xcd5u); expected=c;
    put(TEB+0x24,123);
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==1);
    expected.eax=123; expected.eip=0x401005; expected.esp+=4;
    CHECK(!memcmp(&c,&expected,sizeof c) && get(TEB+0x34)==999);
    c=setup(0); put(TEB+0x24,0); expected=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-2 && fault==TEB+0x24);
    CHECK(!memcmp(&c,&expected,sizeof c) && get(TEB+0x34)==999);
    c=setup(0); c.fs_base=UINT32_MAX-0x10u; expected=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && fault==UINT32_MAX);
    CHECK(!memcmp(&c,&expected,sizeof c));
    put(TEB+0x24,1);
    api.name="SetHandleCount";
    const uint32_t requested_counts[]={0,512,UINT32_MAX};
    for (unsigned i=0;i<sizeof requested_counts/sizeof requested_counts[0];i++) {
        c=setup(0); put(STACK+4,requested_counts[i]); eflags_set(&c,0xcd5u); expected=c;
        CHECK(guest_windows_import(&c,&api,NULL,&fault)==1);
        expected.eax=requested_counts[i]; expected.eip=0x401005; expected.esp+=8;
        CHECK(!memcmp(&c,&expected,sizeof c) && get(TEB+0x34)==999);
    }
    c=setup(0); c.esp=UINT32_MAX-3; expected=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && fault==c.esp);
    CHECK(!memcmp(&c,&expected,sizeof c));
    return 0;
}
int main(void) {
    CHECK(!guest_memory_init());
    CHECK(!guest_memory_commit(STACK,0x30000));
    CHECK(!tls_contract());
    GuestImport api={0,"KeRnEl32.DlL","GetVersionExA"}; uint32_t fault=0;
    GuestWindows windows={.image_base=0x400000u};
    for (uint32_t size=148; size<=156; size+=8) {
        memset(g_mem+BUFFER,0xab,160);
        CPU c=setup(size);
        CHECK(guest_windows_import(&c,&api,NULL,&fault)==1);
        CHECK(c.eax==1 && c.esp==STACK+8 && c.eip==0x401005u);
        CHECK(c.ebx==0xbad12345u && c.ecx==0xabcdef12u);
        CHECK(get(BUFFER)==size && get(BUFFER+4)==5 && get(BUFFER+8)==1);
        CHECK(get(BUFFER+12)==2600 && get(BUFFER+16)==2);
        CHECK(get(TEB+0x34)==999 && g_mem[BUFFER+size]==0xab);
        for (unsigned i=20;i<148;i++) CHECK(!g_mem[BUFFER+i]);
        if (size==156) CHECK(get(BUFFER+148)==0 && get(BUFFER+152)==0x00010100u);
    }
    CPU c=setup(147), before=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==1 && !c.eax);
    CHECK(get(BUFFER)==147 && get(TEB+0x34)==122 && c.esp==STACK+8);
    GuestImport unknown={0,"KERNEL32.dll","NeverPretendSuccess"};
    c=setup(148); before=c;
    CHECK(!guest_windows_import(&c,&unknown,NULL,&fault) && !memcmp(&c,&before,sizeof c));
    unknown.library="USER32.dll"; unknown.name="GetVersionExA";
    CHECK(!guest_windows_import(&c,&unknown,NULL,&fault));
    c=setup(148); c.esp=0xfffffffcu; before=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && fault==0xfffffffcu);
    CHECK(!memcmp(&c,&before,sizeof c));
    CHECK(!guest_windows_import(NULL,&api,NULL,&fault));
    CHECK(!guest_windows_import(&c,NULL,NULL,&fault));
    c=setup(148); put(STACK+4,STACK); put(STACK,148); /* output aliases API return */
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==1 && c.eip==148 && c.esp==STACK+8);
    c=setup(148); put(STACK+4,0x23ff0u); put(0x23ff0u,148); before=c;
    CHECK(!guest_memory_protect(0x24000,0x4000,GUEST_MEMORY_NONE));
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && get(0x23ff0u)==148);
    CHECK(!memcmp(&c,&before,sizeof c) && get(TEB+0x34)==999);
    CHECK(!guest_memory_protect(0x24000,0x4000,GUEST_MEMORY_READ_WRITE));
    GuestImport heapapi={0,"KERNEL32.dll","HeapCreate"};
    c=setup(0); put(STACK+4,0); put(STACK+8,4096); put(STACK+12,0);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax==GUEST_HEAP_BASE);
    uint32_t heap=c.eax;
    CHECK(c.esp==STACK+16 && guest_memory_pointer(heap,0x8000u,1) && get(TEB+0x34)==999);
    heapapi.name="HeapAlloc"; c=setup(0); put(STACK+4,heap); put(STACK+8,8); put(STACK+12,31);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax && !(c.eax&7));
    uint32_t allocation=c.eax;
    for (unsigned i=0;i<31;i++) CHECK(!g_mem[allocation+i]);
    heapapi.name="HeapSize"; c=setup(0); put(STACK+4,heap); put(STACK+8,0); put(STACK+12,allocation);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax==31);
    c=setup(0); put(STACK+4,heap); put(STACK+8,0); put(STACK+12,allocation+1);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax==UINT32_MAX && get(TEB+0x34)==999);
    heapapi.name="HeapFree"; c=setup(0); put(STACK+4,heap); put(STACK+8,0); put(STACK+12,allocation);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax==1);
    c=setup(0); put(STACK+4,heap); put(STACK+8,0); put(STACK+12,allocation);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && !c.eax && get(TEB+0x34)==87);
    heapapi.name="HeapAlloc"; c=setup(0); put(STACK+4,heap); put(STACK+8,0); put(STACK+12,UINT32_MAX);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && !c.eax && get(TEB+0x34)==999);
    heapapi.name="HeapCreate"; c=setup(0); put(STACK+4,0x40000); before=c;
    CHECK(!guest_windows_import(&c,&heapapi,&windows,&fault) && !memcmp(&c,&before,sizeof c));
    heapapi.name="HeapDestroy"; c=setup(0); put(STACK+4,heap);
    CHECK(guest_windows_import(&c,&heapapi,&windows,&fault)==1 && c.eax==1 && c.esp==STACK+8);
    CHECK(!guest_memory_pointer(heap,1,0));
    c=setup(148); put(STACK+4,0xfffffffcu); put(0x20000u,0x12345678u); before=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && fault==0xfffffffcu);
    CHECK(!memcmp(&c,&before,sizeof c));
    c=setup(148); CHECK(!guest_memory_protect(0x20000,0x4000,GUEST_MEMORY_READ)); before=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1 && fault==BUFFER);
    CHECK(!memcmp(&c,&before,sizeof c) && get(TEB+0x34)==999);
    CHECK(!guest_memory_protect(0x20000,0x4000,GUEST_MEMORY_READ_WRITE));
    c=setup(147); c.fs_base=0xfffffff0u; before=c;
    CHECK(guest_windows_import(&c,&api,NULL,&fault)==-1);
    CHECK(!memcmp(&c,&before,sizeof c) && get(BUFFER)==147);
    CHECK(fault==UINT32_MAX);
    GuestImport module={0,"KERNEL32.dll","GetModuleHandleA"};
    c=setup(0); put(STACK+4,0);
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==1 && c.eax==windows.image_base);
    CHECK(c.esp==STACK+8 && get(TEB+0x34)==999);
    c=setup(0); memcpy(g_mem+BUFFER,"SPEED2",7);
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==1 && !c.eax && get(TEB+0x34)==126);
    CHECK(!guest_memory_commit(0xffffc000u,0x4000));
    c=setup(0); put(STACK+4,0xfffffffeu); g_mem[0xfffffffeu]='a'; g_mem[0xffffffffu]='b'; before=c;
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==-1 && fault==UINT32_MAX);
    CHECK(!memcmp(&c,&before,sizeof c));
    c=setup(0); memcpy(g_mem+BUFFER,"sPeEd2.ExE",11);
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==1 && c.eax==windows.image_base);
    c=setup(0); memcpy(g_mem+BUFFER,"missing.dll",12);
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==1 && c.eax==0);
    CHECK(get(TEB+0x34)==126 && c.esp==STACK+8);
    c=setup(0); memset(g_mem+BUFFER,'a',260);
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==1 && !c.eax && get(TEB+0x34)==126);
    c=setup(0); put(STACK+4,0xff000000u); before=c;
    CHECK(guest_windows_import(&c,&module,&windows,&fault)==-1 && fault==0xff000000u);
    CHECK(!memcmp(&c,&before,sizeof c));
    const uint32_t addresses[]={0x401000u}; const GuestFunction functions[]={caller};
    GuestDispatch table={0}; CHECK(!guest_dispatch_init(&table,0x401000u,0x1000,addresses,functions,1));
    GuestExecutionConfig config={.dispatch=&table,.imports=&api,.import_count=1,
        .instruction_budget=10,.depth_limit=4,.timeout_ns=1000000000,
        .import_handler=guest_windows_import};
    GuestExecutionResult result;
    c=setup(148); CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_RETURN && result.imports_handled==1 && result.instructions==2);
    CHECK(c.esp==STACK+8 && c.eax==1 && result.calls==2);
    c=setup(147); CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_RETURN && result.imports_handled==1 && !c.eax && get(TEB+0x34)==122);
    GuestImport malformed={0,"KERNEL32.dll",NULL}; config.imports=&malformed;
    CHECK(guest_execution_run(&config,&c,0x401000u,&result)==EINVAL);
    config.imports=&unknown; c=setup(148); before=c;
    CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_IMPORT && !result.imports_handled && c.esp==before.esp);
    config.imports=&api; c=setup(148); put(STACK+4,0xff000000u); before=c;
    CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_MEMORY && result.target==0xff000000u && !result.imports_handled);
    CHECK(c.esp==before.esp && c.eax==before.eax);
    const uint32_t section=0x38001u;
    GuestImport critical={0,"KERNEL32.dll","InitializeCriticalSection"};
    put(TEB+0x24,1);
    c=setup(0); c.eax=0xb16b00b5u; put(STACK+4,section);
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==1);
    CHECK(c.eax==0xb16b00b5u && c.esp==STACK+8 && get(TEB+0x34)==999);
    CHECK(guest_critical_count(&windows.critical)==1 && get(section+4)==UINT32_MAX);
    critical.name="EnterCriticalSection";
    c=setup(0); c.eax=1234; put(STACK+4,section);
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==1 && c.eax==1234);
    CHECK(get(section+4)==0 && get(section+8)==1 && get(section+12)==1);
    critical.name="TryEnterCriticalSection"; c=setup(0); put(STACK+4,section);
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==1 && c.eax==1);
    CHECK(get(section+8)==2 && get(TEB+0x34)==999);
    put(TEB+0x24,2); c=setup(0); put(STACK+4,section);
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==1 && !c.eax);
    CHECK(get(section+8)==2 && get(TEB+0x34)==999);
    critical.name="EnterCriticalSection"; c=setup(0); put(STACK+4,section); before=c;
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==-2 && fault==section);
    CHECK(!memcmp(&c,&before,sizeof c) && get(section+8)==2);
    put(TEB+0x24,1);
    critical.name="DeleteCriticalSection"; c=setup(0); put(STACK+4,section); before=c;
    CHECK(guest_windows_import(&c,&critical,&windows,&fault)==-2 && fault==section);
    CHECK(!memcmp(&c,&before,sizeof c) && get(section+8)==2);
    critical.name="LeaveCriticalSection";
    for (unsigned i=0;i<2;i++) {
        c=setup(0); c.eax=4321; put(STACK+4,section);
        CHECK(guest_windows_import(&c,&critical,&windows,&fault)==1 && c.eax==4321);
    }
    CHECK(get(section+4)==UINT32_MAX && !get(section+8) && !get(section+12));
    critical.name="EnterCriticalSection";
    config.imports=&critical; config.import_context=&windows;
    c=setup(0); put(STACK+4,section+64); before=c;
    CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_API_STATE && result.target==section+64);
    CHECK(c.esp==before.esp && !result.imports_handled && result.instructions==1);
    /* A budget stop after a real acquire must still release native resources. */
    config.instruction_budget=1; c=setup(0); put(STACK+4,section);
    CHECK(!guest_execution_run(&config,&c,0x401000u,&result));
    CHECK(result.stop==GUEST_STOP_BUDGET && result.imports_handled==1 && get(section+8)==1);
    CHECK(!guest_windows_cleanup(&windows) && !guest_critical_count(&windows.critical));
    CHECK(!guest_windows_cleanup(&windows));
    guest_dispatch_destroy(&table); CHECK(!guest_memory_shutdown());
    puts("PASS | Windows compatibility bridge | version/module/heap/critical/TLS contracts + stdcall + LastError + strict faults/unknown APIs + stop cleanup");
    return 0;
}
