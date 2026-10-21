# Strict startup parity repair

The private native harness compares the exact import boundary, instruction and
CALL counts, maximum guest call depth, instruction trace, GPR/EFLAGS, heap
metadata, process references and image/TEB/stack/heap/process memory hashes.
An expected unimplemented API stop is a verified prefix, not game boot.

The old nonzero trace/hash alternatives and historical count alternatives were
removed in `f233875`. Synthetic C harness mutations must now fail individually.

## Root causes and independent evidence

1. Private run [39565389780](https://github.com/lyszq/NFSU2Recomp-ios-private/actions/runs/39565389780)
   proved an unresolved indirect JMP: source `0063d13c`, target `0063d129`.
   The oracle observed CALL targets but omitted this dynamically resolved JMP
   target from the generation seed list. Generation now requires both sets.
2. A JMP reuses the existing x86 return frame. The new tail dispatcher drains
   targets iteratively at the current guest depth. Only actual CALLs and the
   initial entry dispatch increase the CALL counter. Synthetic tests exercise
   20,001 tail transfers, native returns, imports, faults and depth limits.
3. Unicorn 2.1.4 produces repeated code hooks inside REP string instructions,
   including a final ECX=0 callback. Native generated code has one instruction
   hook around that loop. The oracle retains raw hook count/trace separately
   and coalesces consecutive same-IP REP callbacks for architectural trace
   comparison. The original instructions still execute every iteration.
   Synthetic tests cover ECX=0/1/2, early REPE exit and branching back to REP.
4. Strict run [39567283091](https://github.com/lyszq/NFSU2Recomp-ios-private/actions/runs/39567283091)
   located the first GPR difference at step 6612, immediately after LCMapStringW:
   Python Unicode uppercase expanded sharp-s, giving 257 instead of 256.
   Later branch differences came from incorrect Unicode CTYPE handling. Both
   the native even/odd Latin classification guess and the oracle's defined-only
   classification of CP1252 extension letters were wrong.

`capture_windows_nls.py` calls real Windows kernel32 APIs on synthetic bytes
0..255. The checked fixture records its actual Windows version and locale 0409;
it is not an XP capture. ANSI CTYPE agrees with the existing table for all 256
values. The capture separately establishes Unicode types and ANSI/Unicode case
maps: sharp-s and micro-sign remain unchanged, and small F with hook maps to
capital F with hook. No game input is involved in this fixture.

Native and independent Unicorn tests each compare their API outputs against
that external capture, including embedded NULs with explicit counts, buffer
guards, LastError and stdcall state. Additional CP1252 conversion tests preserve
the five undefined byte positions as controls and exercise the verified F-hook
best-fit mapping and WC_NO_BEST_FIT_CHARS.

The corrected independent startup reference has 117395 architectural
instructions, 129082 raw Unicorn callbacks, 6781 CALL/entry dispatches, depth 12,
558 API invocations and a RegOpenKeyA stop. These numbers follow the corrected
Windows contracts; they are not alternatives accepted by the native harness.
The native run must exactly match the generated independent reference.

The heap oracle also had two independently reproduced defects: undefined
page-growth helper calls and unconditional successful HeapFree on invalid
handles/pointers. Synthetic heap tests cover their repairs; neither dormant
reallocation page-growth path explained the observed NLS divergence.

## Limits

The locale implementation remains a bounded CP1252 profile, not a complete
Unicode NLS implementation. The existing renderer/audio/input bridges and
128-shard groundwork are not validated by startup parity. Host Linux/macOS
native execution and an ARM64 IPA build do not prove physical-iPad execution,
signing entitlements, game rendering, full boot or gameplay.

Contract references: [LCMapStringW](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-lcmapstringw),
[GetStringTypeW](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-getstringtypew),
[Windows case mapping](https://learn.microsoft.com/en-us/windows/win32/intl/handling-sorting-in-your-applications).
