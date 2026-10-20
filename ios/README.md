# NFSU2 iOS Stage 3 — shared native guest memory

Version 0.3 keeps the SwiftUI/Metal bootstrap and executable validator. It does
not boot NFSU2, include lifted game functions, or contain game data.

## Code actually shared with macOS

`runtime/guest_memory.c` now owns `g_mem`, the 4 GiB offset reservation and the
16 KiB compatibility bitmap used by `runtime/cpu.h` without changing the CPU layout or memory macros. The desktop
`runtime/mem.c` delegates reservation/commit/accounting to this same C module;
its PE loader, watchpoints, signal handlers and debug callbacks stay desktop-only.
`link.sh` and the standalone ISA/fuzz build commands link the new module.

The iOS target compiles `guest_memory.c` directly as native ARM64 C. It also
compiles `ios/tests/cpu_flags_test.c` and the bridge `Native/GuestSmoke.c`.
No AppKit, guest dispatch, interpreter, generated game code or desktop renderer
is linked into the iOS target yet. No JIT or executable guest pages are used.
`-fno-strict-aliasing` is preserved for the upstream typed guest-memory accesses.

## Memory contract

- Reserve 4 GiB of **virtual address space**, initially inaccessible; backing is
  touched only when accessed. Commit granules remain 16 KiB, preserving existing
  generated-code offsets and bitmap layout on 4 KiB and 16 KiB host pages.
- Safe APIs return errno values instead of terminating the app. Reject ranges
  crossing the end of 32-bit space, including overflow of a 64-bit length.
  Register arithmetic such as ESP still wraps at 32 bits; multibyte host-memory
  access does not wrap. There is no segmented fallback if reservation fails.
- Zero-length commit/protect does nothing. Repeated/overlapping commits count
  unique granules, fixing the desktop counter's repeated-request overcount.
  The legacy desktop `mem_commit` still clips ranges at 4 GiB; the safe API rejects
  them. The old unaligned zero-length desktop commit no longer allocates a page.
- Protection supports NONE, READ and READ_WRITE, never EXECUTE. Protect rounds
  outward and requires allocated granules. NONE revokes access and clears the
  compatibility readability bitmap; it does **not** discard backing/contents or
  reduce the committed-byte count. Recommit restores RW without zeroing.
- Metadata mutation/queries use a mutex. Compatibility bitmap publication and
  `mem_is_committed` reads are atomic so concurrent commits cannot race there. Callers must quiesce guest execution
  before protection changes or shutdown; raw `MR*` access is intentionally not
  locked or bounds-checked. The smoke test requires an idle guest runtime.
- `guest_memory_pointer` checks the entire range and access permission. Its result
  remains valid only while the owner keeps the mapping and permissions stable.

## Validation

Run on macOS or 64-bit Linux from the repository root:

```sh
bash tests/run_guest_tests.sh /tmp/nfsu2-guest-tests
```

The suite uses no proprietary inputs:

- 393,216 exhaustive 8-bit ADD/SUB/ADC/SBB cases against widened arithmetic;
  22 16/32-bit boundary cases, 240 flag-mask cases and 128 EFLAGS patterns.
- Memory boundary/overflow, overlap accounting, every bitmap position,
  checked translation, lifecycle reset and eight concurrent commit callers.
- Host-only child processes verify that uncommitted, read-only and inaccessible
  mappings actually fault on forbidden access. These fault probes and the
  full-space bitmap sweep run only in host CLI tests, never in the app.
- The iOS smoke path verifies low/PE/heap/high/final addresses, protections,
  checked range failures, CPU register storage and upstream PUSH/POP across
  granules and through ESP wrap. The host CLI runs that same path twice.
- macOS additionally links/tests the desktop `mem.c` adapter without game code.
- Actions builds the unsigned IPA and requires ARM64 plus live link-map symbols
  from the shared core/CPU tests. Artifact `NFSU2iOS-shared-runtime-evidence`
  contains host test output and the linkage checks.

The device test runs on a worker queue. Press **RUN CPU + MEMORY TEST**, then
**Share test diagnostic** to copy/share the full PASS or FAIL with app version,
OS and device family. Repeat once to check lifecycle reset. Signing is still
required before installation. Bundle ID and Application Support save path stay
`dev.lyszq.nfsu2ios` and `NFSU2/Game/SPEED2.EXE`; use the same signing identity
and upgrade installation to preserve the already imported executable.

A successful CI test is not an iPad result. v0.1 was physically confirmed; the
handoff's v0.2 and this v0.3 still require the user's device diagnostic.

## Next engine milestone

Validate this shared mapping on the iPad, then privately generate/compile a
small verified function from the supported local EXE and connect real dispatch.
Keep game-derived source, binaries and assets outside public Git and Actions
artifacts. The desktop D3D9/Metal frontend still needs its AppKit lifecycle split
before it can attach to the existing iOS MTKView.


## Stage 4: real image loading and private lifted-function build

On 20 October 2026 the user supplied a physical-device v0.3 PASS from iPadOS
26.3 with 16 KiB host pages. This confirms the shared memory and CPU/stack smoke
path on that iPad. It does not establish gameplay or the new image probe.

Version 0.4 adds a bounded PE32/i386 loader (`runtime/guest_pe.c`). The app
reauthenticates the saved EXE's size and SHA-256 on the runtime worker queue,
then loads the actual headers and sections at the preferred guest addresses,
zero-fills virtual tails and reports the entry address. It releases the test
mapping afterward. No imports, relocations, TLS startup or entry execution are
performed. Synthetic host fixtures test malformed inputs without game data.
All native app probes share one serial queue to keep mapping ownership clear.
Format reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

`tools/ios_private/README.md` describes the separate private build. That flow
lifts the authentic `sub_0048b1e0` already covered by upstream tests, compares
native execution with 48 independent x86 reference cases, and builds version
0.4.1 with that actual generated function linked into ARM64 code. The host-only
Unicorn reference is not bundled into the app. Only the private IPA can run
this function probe; the public IPA reports image loading only. Neither boots
the engine or provides gameplay.


## Stage 5: real entry prefix and strict shared dispatch

On 20 October 2026 the user supplied a physical iPad v0.4.1 PASS for the actual
statically lifted `sub_0048b1e0`, including all 48 x86 reference cases. That
confirms the isolated real function on-device, separately from full boot.

`runtime/guest_dispatch.c` extracts the existing O(1) address-index mechanism.
The macOS `dispatch.c` and native iOS probes both use this implementation.
It rejects duplicate/out-of-range/null entries and has explicit teardown.
`runtime/guest_bootstrap.c` also shares the existing macOS CPU/TEB/PEB/stack
initializer with the private iOS entry probe. The desktop PE loader now exports
its real image size/entry metadata for that initializer. Full macOS gameplay
has not been rerun; CI checks the modified desktop dispatcher and boot syntax.

`runtime/guest_execution.c` is a strict, bounded static execution adapter.
It preserves the upstream CPU and PUSH/POP ABI, validates IAT slots before
binding, and records exact stop reasons. No unresolved call is popped/swallowed;
unsupported instructions, invalid memory, import boundaries, depth, instruction
budget and timeout stop execution. Register/memory effects at a stop remain
visible for diagnostics; this is not rollback or automatic continuation.
The existing desktop dynamic x86 fallback is not linked into this iOS adapter.

Private generation compiles 64 reachable real entry functions plus the previous
leaf regression (a bounded subset, not the complete game). Unliftable functions
are omitted; there are no replacement game-function stubs. Every generated
instruction has a budget/trace hook, direct calls use the shared dispatcher,
and typed memory accesses use checked whole-range translation. Unchecked bulk
operations and desktop no-op traps stop explicitly. The 14 MiB O(1) lookup table
is currently preserved for consistency; mobile table compression is future work.

The private 0.5.1 probe maps the authentic image and initializes its process
layout, then enters `0x0075bcc7`. Independent original-x86 execution reaches
`KERNEL32.dll!GetVersionExA` at callsite `0x0075bce7` after 40 instructions,
4 dispatcher calls and two actual helper functions. Both implementations stop
before supplying any API result. The native test must match GPR/EFLAGS,
address trace, full image and TEB hashes, and an 8 KiB stack window. A matching
result is **VERIFIED ENTRY STOP**, never a full-boot or gameplay PASS.

Next: implement the actual `GetVersionExA` compatibility contract, then continue
through subsequent module/command-line/CRT imports with explicit diagnostics.
The app still has no game renderer, audio, input or playable scene.


## Stage 6: bounded Windows contracts and guest heaps (0.6.1 private)

The shared runner can service implemented imports through an explicit callback.
Unknown APIs or unsupported flags still stop with the unconsumed call frame.
`guest_windows.c` implements GetVersionExA, GetModuleHandleA, HeapCreate,
HeapAlloc, HeapFree, HeapSize and HeapDestroy. These are compatibility contracts,
not claims about the host iPad OS. The selected guest profile is XP 5.1.2600,
NT/workstation, Personal suite, no service pack. Main-module queries recognize
NULL or the case-insensitive exact SPEED2.EXE identity. No other DLL is loaded.

`guest_heap.c` supplies actual checked guest allocations with 8-byte alignment,
zero-memory support, reuse of freed gaps, size queries and destruction that
revokes access. Four disjoint 64 MiB arenas with 256 live blocks each are current
resource limits. Fixed heap limits and the 32-bit large-block cutoff are checked.
This is a bounded allocator, not the desktop Windows heap implementation.
The bootstrap TEB must remain valid; one serialized guest thread owns this state.
Executable or exception-generating heap options stop as unsupported. There is
no GetProcessHeap, HeapReAlloc, guest thread creation or filesystem bridge yet.

The independent x86 reference now services the declared contracts and reaches
InitializeCriticalSection at 0x0076c3aa after 154 original instructions, 15 calls,
maximum depth 5 and four API invocations (version, module, heap, module).
The native private probe must match those counts, the exact instruction-address
trace, GPR/EFLAGS, image/TEB/stack hashes and the 32 KiB committed guest heap.
Static generation prioritizes observed authentic call targets, then expands the
bounded graph; all executed functions must have real lifted bodies or generation
fails. Native execution remains ARM64 static code without JIT or an interpreter.

Host tests cover heap exhaustion, failed-allocation atomicity, freed-gap reuse,
protection, stdcall cleanup, structure layouts, LastError preservation, aliased
outputs, malformed memory and unsupported imports. On 20 October 2026 the user
supplied an iPadOS 26.3 screenshot confirming both 0.6.1 CPU/memory PASS (16 KiB
pages) and the expected 154-instruction entry stop with full state/hash match.
This confirms 0.6.1 on-device; it still has no game boot, renderer, audio or input.

API references:
- https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa
- https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
- https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
- https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
- https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapsize


## Stage 7: native critical sections (0.7.1 private)

`runtime/guest_critical.c` implements guest critical sections using real native
recursive pthread mutexes. The Windows bridge now services Initialize, Enter,
TryEnter, Leave and DeleteCriticalSection with checked 24-byte guest structures,
recursive ownership, stdcall cleanup and LastError/void-return preservation.
Host mutex pointers stay outside guest memory. Duplicate/overlapping objects,
invalid ownership, guest mirror corruption and the 64-object cap are explicit
errors. TryEnter contention returns false; Enter contention stops as API_STATE
because the current single guest-thread runner cannot schedule a waiter. It
never pretends a contended lock was acquired, and never blocks past the budget.

The caller must quiesce section lifecycle and guest mapping changes. Native
acquire/release contention is tested with actual pthreads. Process teardown
frees native mutex state after every execution stop, including budget longjmp;
it can cancel recursive locks held by its own worker even after VM shutdown.
Guest thread creation and general multithreaded game execution remain pending.

The original-x86 reference now initializes 14 CRT critical sections and reaches
KERNEL32.dll!TlsAlloc at 0x00762021 after 1,115 instructions, 82 calls and 18
implemented API invocations. The bounded static generator includes every
observed real function. The native private test must match the full trace,
GPR/EFLAGS, image/TEB/stack/heap hashes, call/depth counts and 14 native section
objects, then clean up all native resources. TlsAlloc remains unimplemented.

The 48-case actual leaf regression remains in the same device button. Version
0.7.1/build 11 needs separate physical-device confirmation; the last confirmed
build is 0.6.1. No gameplay or successful complete CRT/game boot is claimed.

API references:
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-entercriticalsection
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-leavecriticalsection
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-deletecriticalsection
