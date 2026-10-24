# Post-v0.25 performance investigation — source work in progress

## Build authorization — 2026-10-24

After five source development rounds, the owner explicitly requested GitHub
compilation ("tamam githubda derlemeye ver"). This supersedes the earlier build
hold for this reviewed delivery. The full target is now 0.26.0/build33. Submit
the exact source commit through the existing public-runner/private-output lane;
preserve its owner-reviewed environment and private output. The round notes
below record historical source-only work, not successful build/device evidence.

## Evidence

The supplied appended `NFSU2Runtime.log` contains nine session headers. The full
v0.25.0/build32 session is the eighth header, source
`142a2072020d70a3a0b46f1ed5f7123c850c22a8`, original lines 47683–78961.
The ninth header is a four-line relaunch, not the whole v0.25 capture.
The input log remains unchanged in the owner's LocalSend folder; do not publish
raw runtime logs with source changes.

The full v0.25 session has 92 cumulative performance records through elapsed
998.178 seconds:

- 31,034,619 PSO lookups, 31,034,558 hits, 61 entries, 156.696 ms variant-PSO
  compilation. This timing excludes shader library source compilation.
- 2,098 reads / 240,468,267 bytes; 51 directory scans; 2,769 case-cache hits.
  The directory cache and PSO lookup index are working; these counters do not
  establish a meaningful device speedup.
- Three audio Play calls, zero reissues, one active buffer at the sampled points.
  Repeated Play calls do not explain the reported audio repetition. Aggregate
  write counts cannot establish whether the active buffer has fresh PCM.
- Two approximately 40.6 MB bursts across 65 reads each occur in the sample
  intervals ending at 220.447 and 693.686 seconds. The log has no path/read-time
  attribution, so storage latency and guest decoding cannot yet be separated.
- Foreground guest-lock holds around 0.8–1.1 seconds occur around audio-clock
  114–120 and 523–555 seconds. Return sites include PeekMessageA, input, and
  Present; they are last call sites, not sampled execution stacks.
- The 6.594 and 46.602 second lock records immediately follow background /
  interruption / foreground transitions. Exclude them from foreground stall
  claims. Audio time and elapsed wall time differ across these lifecycle gaps.
- There are 3,219 full event-table dumps in this session, written synchronously
  while guest execution is serialized.

## Local changes

1. Track guest-lock ownership per host thread. A paired host-wait API releases
   the guest mutex only for an actual owner and restores that thread's CPU on
   reacquisition. Non-guest callers receive a no-op token. Timings measure the
   released interval including guest-lock reacquisition; no backend mutex may
   be held during reacquisition.
2. Release the guest lock while Present waits on the render-queue condition.
   Restore lock order and recheck queue state after waking. Preserve buffer
   ownership and the existing timed/late-wait policy. A qlock-protected publish
   serial gives a replacement frame its own deadline if another guest producer
   publishes while the original caller is waiting. This removes a concrete
   path that kept the audio producer waiting for the renderer; device impact
   is unmeasured.
3. Skip repeated memory-protection system calls only when every requested
   memory granule is already allocated, readable and writable. Recommitting
   read-only or inaccessible memory keeps the previous restoration behavior.
4. Gate full event-table dumps behind `WAITLOG=1`, leaving the bounded stall
   checker active. Expand rare long-lock records with wall time, guest thread,
   critical-section depth and the last import name.
5. Add bounded, nonblocking per-buffer audio and callback measurements and
   lightweight shader-library / upload / frame-stage measurements to the
   existing ten-second asynchronous log. Age of a static loop is not an underrun
   verdict. Commit interval maxima include lifecycle gaps.
6. Measure memory preparation separately from synchronous read/completion time
   using three monotonic timestamps per read, without per-read output or data
   copies. This instrumentation deliberately adds bounded timing cost to resolve
   the missing load attribution in v0.25.
7. Require the new host-wait and renderer-snapshot functions to come from their
   real backend objects in a future full-link verification.

## Development round 2

- The iOS full runtime polls for cooperative handoff every 128 Win32 imports
  and after Present's COM/stdcall epilogue. Handoff requires a queued guest
  worker, at least two milliseconds since acquisition, and no tracked critical
  section. A condition-variable handoff releases the actual guest mutex until
  another execution owner acquires it; acquisition generation excludes cleanup
  and the sleeper's own spurious reacquisition. This replaces the iOS import-
  count-based yield and periodic nanosleep. The deadline uses the condition
  variable's realtime clock. Round 3 bounds each opportunity with one deadline
  rather than renewing it behind a descheduled waiter. This is cooperative
  scheduling, not a two-millisecond preemption
  guarantee for pure guest computation or critical sections.
  Import-only loops retain the existing pause/lifecycle checkpoint every 1024
  imports with the guest mutex released, even when there are no queued workers.
  A TLS COM-depth counter excludes a Present reentered through a guest callback
  while an outer COM call is still active.
- Added acquisition wait, queued-worker and handoff counters. Existing host-wait
  counters continue to measure renderer waits separately.
- DirectSound Lock honors FROMWRITECURSOR for registered buffers and retains
  the legacy fallback cursor for unregistered buffers. If the second output
  pointer is absent, the wrapped portion is left unlocked. These follow the
  [Microsoft Lock contract](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/mt708932(v=vs.85));
  the v0.25 log does not establish whether the game used this flag.
- The mixer reads a host-owned PCM mirror instead of racing guest writes.
  Registration copies initial content outside the callback/mixer mutex;
  duplicates share storage. Unlock validates both full guest RAM spans and
  registered-buffer offsets before publishing either region under the mixer
  mutex. Both-region byte counts and producer cursor history are updated in
  that publication. No stale-loop muting, cursor restart or pitch policy change
  is introduced.
- Unique mirror storage is capped at 64 MiB and retained across audio subsystem
  restart, because guest COM buffers survive restart. Failure is explicit;
  CreateSoundBuffer returns E_OUTOFMEMORY rather than exposing an unregistered
  secondary buffer. A cheap advisory preflight rejects known budget/ID exhaustion
  before consuming guest/COM bump-allocation arenas; actual allocation failure
  after that preflight can still leave an unexposed bump allocation. Large copies can still delay the callback while holding the
  existing mixer mutex; publication time and bytes are recorded for evaluation.
  Registration/Unlock callers must hold the guest lock while accessing PCM.
- Exact-source shader-library caching was rejected after reviewing the actual
  translator: generated entrypoints and pixel-shader diagnostic indices embed
  unique IDs, while successful per-ID registration is already cached. A new
  exact-source cache would have no demonstrated useful hit path. Generic GIL
  release during compilation was also rejected: VS IDs are reserved too late,
  and some PS reflection registrations occur while the render queue mutex is
  held. No additional shader cache or compile-yield behavior was added.

No tests, native compilation, application execution, IPA workflow, push or
version/build change was performed in this round. The changes remain local.

## Remaining work

No device speedup, fixed audio repetition or shorter race load is claimed for
this local source. Native tests and iOS compilation of these changes are still
pending; no IPA build is authorized during the hold. The host-wait lock order
received an independent source review; the replacement-frame deadline edge was
corrected afterward. Further work should cover this protocol with a standalone concurrency regression,
and validate PCM publication / DirectSound lock behavior and attribute
shader-library compilation and the active buffer's write gaps.
The bounded outstanding-Lock registry and wait-predicate changes in round 3
still need executable regression coverage before delivery.
Do not mask starvation by muting/restarting legitimate static loops, change the
continuous QPC/TSC clock, or unlock around direct reads into shared guest memory.

## Development round 3

- DirectSound keeps up to 4,096 outstanding Lock records in a host-owned pool.
  Records are hashed by COM object; duplicates have independent lock lists and
  shared PCM storage. Multiple, overlapping and out-of-order locks are allowed.
  Unlock matches both exact returned pointers (including a second pointer when
  its actual write count is zero), and each actual count must fit the matching
  Lock. Identical pointer tuples use the smallest fitting record. This follows
  the [Microsoft Unlock contract](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/mt708941(v=vs.85)).
  Full guest spans are checked before sampling or copying. A failed Unlock
  retains the record for retry; successful zero-byte Unlock consumes its record
  without refreshing PCM age. Release discards pending locks. Pool exhaustion
  returns E_OUTOFMEMORY before exposing Lock outputs; no per-Unlock allocation
  or callback allocation was added.
- PCM nonzero diagnostics sample at most 4 KiB per region once, outside the
  mixer mutex, after validation. The same sample feeds existing COM diagnostics
  and publication accounting. Completed-copy timestamps now describe published
  content rather than time before the mutex/copy. Large actual PCM copies still
  hold the existing mixer mutex and remain a measurement target.
- DuplicateSoundBuffer now obtains a valid mixer ID before consuming COM bump
  storage. Slot exhaustion returns E_OUTOFMEMORY and a null output, rather than
  silently exposing a successful but unregistered duplicate. Primary or invalid
  unregistered sources are rejected explicitly. Existing Release/refcount stubs
  and process-lifetime PCM/ID retention remain a capacity limit.
  Both sound-buffer creation paths check the full output-pointer span and COM
  arena capacity before allocation; the serialized arena preflight precedes
  duplicate ID allocation. CreateSoundBuffer also preflights the aligned guest
  PCM arena request before consuming a COM object; a defensive allocation check
  rejects an unusable buffer before registration. Host allocation failure can
  still leave unexposed bump allocations as described in round 2.
- Cooperative guest handoff keeps one absolute two-millisecond condition-wait
  deadline across spurious wakes and checks process exit. A waiter that the host
  OS has descheduled cannot cause endless deadline renewals. This bounds the
  condition-wait opportunity, not time spent reacquiring the mutex or host
  scheduling latency; queued sleeper counts remain accurate.
- WaitForSingleObject now retains one deadline for finite waits and rechecks
  the predicate after spurious wakes. INFINITE waits keep waiting in two-second
  exit-check chunks instead of falsely timing out after the first chunk. Mutex
  ownership/recursion is preserved; thread handles remain signaled after exit,
  and semaphore waits consume one count. These state transitions follow the
  [Microsoft wait contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).
  The object condition variables still use CLOCK_REALTIME, so wall-clock
  adjustments can shift elapsed timeouts. Existing invalid-handle behavior and
  WaitForMultipleObjects are outside this patch; this is not a complete Win32
  synchronization rewrite.
- Texture initialization reuses one base-mip zero scratch allocation across all
  mip levels and cube faces. The per-mip fallback remains if the shared attempt
  fails, all clears and NOTEXZERO behavior are preserved, and row-size overflow
  is checked. This removes proven repeated allocations/zero fills; no device
  FPS or loading-time improvement has been measured.

No tests were added or run in round 3, and no compilation, IPA workflow, push,
version/build change or device run was performed. Changes remain local.
Independent source review covered the handoff deadline, waiter accounting,
object-mutex/guest-mutex lock order and WaitForSingleObject signal consumption;
it found no concrete regression. This is source review, not concurrency or
device execution evidence.

## Development round 4

- Shader constant setters (vertex float/integer/boolean and pixel float) copy
  the readable whole-register prefix in one bulk operation. Each covered guest
  memory granule is checked once instead of one check and small copy/scalar loop
  per vector. Requests are capped to the destination register array before
  forming a host pointer; 64-bit source arithmetic stops at the 4 GiB boundary.
  Partially readable input copies only complete registers before the first
  inaccessible granule; it never reads across a hole or wraps to address zero.
  No state-setting call is skipped and diagnostic/stateblock hooks remain.
  This uses the same readable bitmap under guest serialization as the previous
  setters; protection/shutdown must quiesce guest execution as documented by
  the guest memory API.
- Audio exact-zero accounting shares the existing clamp/pack pass and tests
  the original unclamped accumulator value. Counters and output ordering are
  retained. Looped source values in [N,2N) use one exact subtraction to normalize
  their cursor; larger values retain fmod, preserving multi-wrap behavior.
  One-shot playback, interpolation, frequency, volume and pitch policy remain.
- The main Metal encoder reuses its previous PSO directly for an adjacent draw
  with the exact same complete 64-bit key, only when that result belongs to the
  actual dense PSO cache. Each new encoder invalidates this shortcut. Missing
  libraries, cache capacity exhaustion and pipeline compilation failure retain
  their original per-draw fallback/retry behavior; no negative cache is added.
  The postprocess helper continues ordinary lookup. Existing PSO lookup/hit
  counters now describe actual map searches, excluding these direct reuses;
  they must not be treated as total draw counts when comparing logs. The v0.25
  total of 31 million searches establishes frequency, not the unknown fraction
  of adjacent equal keys or a measured speedup.

Independent source review covered constant-array bounds, byte representations,
readable-prefix boundaries and the protection/quiescence contract. A separate
cross-review covered PSO cacheability return paths, complete key identity,
encoder reset/binding sites and shader-ID stability. Neither found a concrete
blocker. Native execution remains pending.

No tests were added or run in round 4. No compilation, IPA workflow, push,
version/build change or device run was performed. Device speedup remains
unmeasured; reduced source-level work is not a benchmark result.

## Development round 5 — 2026-10-24, sustained optimization

The owner requested about one hour of further source work toward smooth 60 FPS
and faster race entry. Work started at 11:30 Europe/Istanbul (08:30 UTC).
The earlier IPA/push hold remains in effect. No test or build is authorized by
this development round; all reviews below are source reviews.

### Native vertex path default

The desktop launcher and bundle host explicitly enable GPUVS. Full iOS builds
exclude both hosts, and the UIKit session did not supply that default. In
`draw_up`, an absent GPUVS resolves to zero and uses the per-vertex CPU shader
interpreter. The session now sets GPUVS=1 before COM initialization and guest
thread creation, preserving an explicit environment override (including zero).
This was independently traced through project configuration, Swift view init,
session setup, declaration decoding, MSL translation, and buffer ownership.
It is a concrete missing runtime default, not a measured device speedup. The
v0.25 log does not contain the policy value or CPU/GPU draw split, so it cannot
prove the observed device path on its own.

The same session switches from 960x720 through 1440x1080 to 1920x1440
(original log lines 47704-49074); that last selected resolution must be retained
when comparing later device measurements. The UIKit display link already asks
for preferred 60 FPS, and iOS keeps the continuous monotonic guest clock.
Neither frame-rate preference nor render resolution was changed in this round.

The declaration cache now also records typed-load alignment and vertex extent.
GPU submission requires supported attribute widths, naturally aligned offsets
and stride, and attributes fitting the vertex. Raw uploads realign their base;
the guest source pointer does not need that alignment. Unsupported or unaligned
layouts take the CPU route. Existing translation/library and arena failure
fallbacks remain. A later render-pipeline creation failure still uses the legacy
default pipeline; CPU retransformation on that failure is not implemented, and
visual/native validation of the enabled GPU route remains necessary.

### Recurring draw work

- Sampler packing and texture-coordinate projection use four-stage dirty masks.
  Each changed stage is rebuilt once before drawing; repeated draws reuse the
  packed values. The raw guest states remain available to D3DX/state-block
  comparisons, and initial/default Reset states invalidate all four stages.
  All raw writers and backend setters were audited; state-block Apply goes
  through the ordinary setters, while Capture and D3DX no-op checks only read.
- Main-encoder vertex buffer bindings at slots 1/2 cache both buffer identity
  and offset. New encoders invalidate both. CPU/fixed-function draws and helper
  encoders do not overwrite those main-encoder slots behind the cache. This
  follows the Metal [vertex argument table contract](https://developer.apple.com/documentation/metal/mtlrendercommandencoder/setvertexbuffer(_:offset:index:)).
- The GPU shader/layout lookup first checks its last dense-table slot, comparing
  both complete keys and reading that entry's live state. Adjacent draws avoid
  scanning the table without changing failed/in-progress-entry behavior, shader
  IDs, compilation policy or capacity.
- The main draw counter is accumulated locally and published once per frame,
  replacing a per-draw atomic increment. GPU-VS and CPU/fixed-function draw
  counts are published in the same batches; helper/fused postprocess draws are
  excluded from that split. The ten-second runtime log also includes cumulative
  committed frames, interval commit FPS and its sample-window length. A zero
  first window is not a measured zero FPS; lifecycle gaps remain included.
  Command-buffer commits do not prove physical display FPS or scene correctness.

### Race resource preparation

- An RW commit checks its existing allocated/readable/writable prefix under the
  metadata mutex, then protects and updates only the remaining suffix. This
  avoids repeatedly processing the monotonic resource allocator's overlapping
  one-MiB cushion. One mprotect still precedes metadata writes, allocation
  accounting remains per newly allocated granule, and explicit protection
  changes retain their full-range behavior.
- WATCHADDR configuration is parsed once with pthread_once; absent diagnostics
  no longer scan the process environment on every resource/heap commit. An
  atomic one-fire guard preserves the watch setup under concurrent commits.
- Texture clearing reuses one never-written, four-MiB BSS zero source for
  ordinary base mips. Larger mips retain the calloc/per-mip fallback. No face or
  mip clear is removed or deferred. This adds four MiB of virtual BSS with
  demand-driven physical residency, removes common per-texture allocation/zero
  fill work, and does not remove the required texture memory copies.
- Consecutive ordered texture uploads share one Metal blit encoder. Every
  buffer/texture copy retains its order and original arguments; the batch ends
  before any draw, clear, texture blit or other record. Existing framebuffer
  chain comparison is handled before the run, and upload records cannot belong
  to such a chain. The two v0.25 load bursts each include roughly 5,500 uploads;
  this establishes frequency, not how many encoder batches or seconds are saved.
- Texture and cube creation have scoped autorelease pools. These entry points
  run on guest pthreads that do not otherwise supply a local pool; temporary
  Objective-C objects can now drain after each resource is published into the
  strong texture table. Required resource lifetime and clearing are retained.
  ARC may already elide some temporary retains; memory savings are unmeasured.

### Mirror retirement and scheduling evidence

The indexed vertex/index pool previously retired free ranges only by waiting
eight guest Presents. Presents can advance while all three framebuffer leases
remain GPU-busy, including when pending frames are replaced after timeout.
Thus, eight Presents do not prove that an old command buffer stopped reading
that shared-buffer range. This is a conditional source-level lifetime gap,
not an observed corruption in the supplied v0.25 log.

Free ranges now also record the serial of the current unpublished guest frame,
which can already contain draws using the old range. Each framebuffer lease
records its claimed serial under the queue mutex before encoding starts and
keeps it until the command-buffer completion callback. Reuse requires all
pending/encoding/in-flight frames at or before retirement to be gone, as well
as the existing eight-Present delay. Dropped frames cease to block naturally;
completion callbacks can finish out of order without advancing past another
live lease. The safe-serial snapshot is computed once only when an aged free
candidate exists. No GPU wait or main-thread blocking loop was introduced.
The retirement boundary uses Metal's documented
[completed-handler contract](https://developer.apple.com/documentation/metal/mtlcommandbuffer/addcompletedhandler(_:)):
the handler runs after GPU execution, rather than merely after scheduling.
Two independent source reviews traced pool readers (including synchronous
optional RT helpers), pending-frame replacement, free-block splitting, pool
growth, pre-commit encoding, and out-of-order completion without finding a
concrete premature-reuse path in the revised protocol.

Host-wait duration now rejects a missing start timestamp, and the fair-handoff
counter advances only if another guest owner actually ran. WaitForSingleObject
distinguishes host clock/condition errors from timeout, sets LastError only
after restoring the guest lock, and guards deadline arithmetic. Signaled objects
still win before a wait is necessary. These changes keep the new performance
evidence interpretable and preserve the bounded cooperative-handoff policy.
Audio producer-gap/age and publish/callback-duration measurements likewise
ignore invalid zero clock samples. A write still counts and publishes its PCM;
a missing timestamp invalidates the gap baseline instead of manufacturing an
uptime-sized latency. This correction does not change playback or freshness.

Final independent source reviews also checked the scalar MSL input loads against
the declaration guard, immutable declaration/shader identities, nested CPU/GPU
draws, encoder recreation, and compilation's lack of guest-lock yield. The wait,
default-policy and FPS format/window changes received a separate cross-review.
No concrete remaining defect was identified in those scoped reviews; this does
not substitute for compilation or device acceptance.

### Deliberately retained constraints

Shader-ID sharing was rejected: IDs participate in postprocess selection,
generated diagnostic slots and masks. A parser-only exact-byte cache would not
avoid library compilation and has no demonstrated hit rate. Cold VS libraries
still compile synchronously on first use; the new timing fields can attribute
that cost. File reads remain serialized into guest memory with their existing
handle/offset/event semantics. Read service and guest commit times are separate
metrics; no unsafe unlocked read or speculative asset prefetch was introduced.
The M2 session reports hardware BC support, so software DXT decode was not
treated as its demonstrated loading bottleneck.

### Next device comparison, when separately authorized

The input log inspected in this round is 7,314,658 bytes, last written
2026-10-22T18:56:11Z. Its SHA-256, captured at final source review, is
`aa8d6bee308c0036c8f06fcb993b27d1d840a8e3cbd5b4d509bef86369736826`.
This identifies the supplied multi-session input, not a run of the edited code.

Retain the same imported game, race, 1920x1440 setting and device conditions.
Separate race-entry wait, the first ten race seconds, and the settled race.
Use the new CPU/GPU draw split to confirm policy execution; distinguish shader
library compilation from pipeline creation, IO service from guest commit work,
and command-buffer commit rate from physical display cadence. Check ring-busy
skips/drops alongside frame intervals, and producer writes alongside callback
gaps before attributing audio repetition to either side. Frame-interval buckets
and cumulative maxima include lifecycle gaps. Compare bucket/count/time sums as
adjacent-sample deltas and exclude explicit background/pause periods. A maximum
cannot be differenced: once a lifecycle gap dominates a cumulative maximum,
that field cannot recover the foreground maximum for a later interval.

Cold resource work, synchronous first-use compilation, and sustained CPU vertex
interpretation are separate mechanisms that can contribute to a slow race start.
The supplied log and source establish candidates and work frequency, not an
exclusive cause or a measured attribution for the entire first-five-to-ten-second
stutter. Stable 60 FPS, shorter loading and resolved audible repetition remain
device acceptance items. This plan does not authorize an IPA build or push.

Source work and cross-review closed at 12:30 Europe/Istanbul (09:30 UTC),
about one hour after starting. Final `git diff --check` passed; HEAD remains
`142a2072020d70a3a0b46f1ed5f7123c850c22a8`, with local edits uncommitted.
All changes are local. No native tests, compilation, IPA, push, version/build
change or physical-device run has been performed for this round. The modified
audio test fixture belongs to the earlier round, not a new test in round 5.
