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
