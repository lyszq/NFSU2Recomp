# v0.19 clock and bounded Toolhelp contracts

This milestone extends the reproducible x86 startup prefix through the
Toolhelp snapshot lifecycle and into the `KERNEL32!GetCurrentProcess` boundary.
It adds an explicit guest clock contract and tightens the snapshot state that
the native probe compares. The current release target is version 0.19.0, build
26. Physical validation for v0.19 is pending; the latest confirmed device run
is v0.17 on iPad / iPadOS 26.3 with 16 KiB pages.

## Guest clock

Windows documents `QueryPerformanceFrequency` as a counter frequency fixed at
system boot, `QueryPerformanceCounter` as a high-resolution counter for
interval timing, and `GetTickCount` as elapsed milliseconds stored in a
wrapping 32-bit value. The guest runtime gives those three APIs one shared
clock contract, while keeping the host implementation separate from the
deterministic startup fixture. See the official
[QueryPerformanceFrequency](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency),
[QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter), and
[GetTickCount](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount)
references.

The native live provider uses `CLOCK_MONOTONIC` nanoseconds with a declared
1,000,000,000-count-per-second frequency. QPF returns that frequency. QPC
returns the sampled monotonic counter, and GetTickCount converts a sample from
that same counter to elapsed milliseconds with the Win32 DWORD wrap. It does
not use wall-clock time. The host provider supplies a monotonic scale suitable
for the guest API; it does not claim identical epochs or scheduler behavior to
Windows.

The independent x86 reference and native startup probe use the named
`deterministic_entry_clock_v1` fixture. It starts at 1,000,000 counts with a
frequency of 1,000,000 counts per second and advances by 1,000 for each QPC or
GetTickCount sample. QPF returns the frequency without advancing the sample.
All calls increment `query_count`; QPC and GetTickCount also increment
`sample_count`. The ordered trace hash folds each API opcode (QPF=1, QPC=2,
GetTickCount=3) and its returned 64-bit value using FNV-1a word steps. A fixture
never reads host time and is not a gameplay-time claim.

At the fresh entry boundary, the fixture state is `mode=1`, frequency
1,000,000, next 1,014,000, increment 1,000, query count 15, sample count 14,
and trace hash 7,840,025,728,631,253,069. The native harness compares every
clock field. It also preflights the complete stdcall frame and output range
before changing guest memory or clock state; null output pointers and malformed
clock state stop explicitly.

## Toolhelp snapshot state

`CreateToolhelp32Snapshot` ignores `th32ProcessID` for a process-list-only
snapshot; the API documentation states that the parameter is used only for
process-specific heap/module selections and is otherwise ignored. This guest
profile accepts only `TH32CS_SNAPPROCESS`, optionally combined with
`TH32CS_INHERIT`. Other flags remain unsupported so a heap, module, thread, or
combined snapshot is not represented as a successful process-only result.

The guest model has eight canonical slots. Each active slot has its slot-derived
handle, the single declared guest process ID, and an enumeration index in the
supported before/after-row states. Inactive rows must be entirely zero and the
stored count must equal the active-row count. Imports validate the full table
before using or changing it; closing a handle clears its slot. This is a
bounded guest process model, not a snapshot of the host's processes. The fresh
reference closes its snapshot before the boundary, leaving an empty snapshot
map. Native parity checks the count and all eight rows, including inactive
slots. The official [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
reference describes the flag and process-ID behavior.

## Exact startup boundary and checks

The independent original-x86 reference stops at
`KERNEL32!GetCurrentProcess`, instruction pointer `0x006f580f`, target
`0xf000009b`. The prefix contains 192,955 architectural instructions,
218,676 raw hooks, 10,541 dispatch calls and 884 handled API calls. It reaches
depth 12, with 15 critical sections and one TLS slot/thread. Generation
registers 1,201 functions, and the reference observes 1,047 unique transfer
targets. Every target executed in the prefix must have a lifted function;
unsupported instructions and APIs remain stops.

The reference also records `deterministic_entry_tsc_v1`, the fixed cursor
fixture `(320,180)`, the upstream static CPUID profile, the bounded cursor
object, image/TEB/stack/heap/process hashes, and process reference counts. The
clock and Toolhelp snapshots are compared alongside those existing values.
The strict startup harness includes sixteen synthetic corruptions covering
trace and memory hashes, process and heap metadata, API/step/depth counts,
Toolhelp state, and clock/TSC hashes; each corrupted result must be rejected.

The next boundary is still unimplemented `KERNEL32!GetCurrentProcess`; this
does not claim a game boot, rendering, audio, or gameplay. v0.19 device QA is
pending and remains separate from native Linux/Darwin parity evidence.
