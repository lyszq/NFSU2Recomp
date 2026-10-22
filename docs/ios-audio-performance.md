# iOS audio correctness and lookup performance (v0.25 / build32)

The owner confirmed that v0.24 opens the game menu and navigates smoothly on a
physical iPad. The next reported issues were repeated recent audio during menu
transitions, unnatural sound, and slow race entry. No v0.24 audio recording or
current reproduction log was available for this change.

## Audio behavior

The DirectSound vtable already exposed `SetCurrentPosition`, but the COM method
resolver and buffer handler returned success without implementing it. The new
handler changes the actual mixer cursor, including a seek while stopped before
the next Play. Invalid offsets return `DSERR_INVALIDPARAM`.

Stop retains the next-sample position, and Play resumes from that position.
Natural one-shot completion resets to the beginning. `GetStatus` and
`GetCurrentPosition` now observe the mixer's state, including one-shot completion
and the `LOOPING` flag. `GetFrequency` reports the effective playback frequency.
These contracts follow Microsoft's [Play](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee418074(v=vs.85))
and [SetCurrentPosition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee418076(v=vs.85)) documentation.

The legacy write-position servo treated every written buffer as a live stream,
including a static effect filled once. Its target could lower playback rate to
0.94. iOS now renders at source rate / hardware rate times the game's explicit
`SetFrequency` ratio. Its continuous monotonic clock, QPC, TSC, and frame pacing
are retained. The desktop virtual-clock/servo policy remains available there.

Render requests larger than the mixer accumulator are split into bounded chunks
so the complete output request is initialized. Production-path PCM regressions
exercise stop/resume, explicit seeks, one-shot completion, legitimate static
loops, sine pitch, resampling, frequency changes, and oversized requests.

The production callback still mixes guest memory under a buffer mutex. A guest
producer stalled longer than a looping buffer can still expose old PCM. The
specific cause of the reported repeats and the perceived quality of v0.25 require
the next physical-device session; synthetic PCM assertions establish narrower
contracts.

## Lookup optimizations

Metal PSO hits previously scanned every dense cache entry. A separate bounded
open-address index now maps the complete 64-bit state key to the existing dense
entry. Full-key equality resolves hash collisions. Pipeline construction, cache
capacity, insertion order, and render state are retained; an index failure uses
the previous dense lookup. The portable fixture covers collisions, high-bit key
differences, duplicate keys, full-table termination, and entry bounds. It prints
comparison/probe counts for 1,350 synthetic draws at several cache sizes.

The file resolver previously rescanned the save directory for each missing
first asset-path component before falling back to the game root. A 64-entry
component cache validates each hit using the parent's device/inode and
nanosecond modification/change timestamps. Mutations and root changes invalidate
entries. Exact-case filesystem checks retain priority. Names that exceed the
cache's storage bypass caching while retaining the resolver's larger bounds.
The production `fileio_call` fixture exercises 500 distinct asset opens and
checks scan reduction, overlay visibility, case priority, LRU eviction, external
changes, and create/delete/rename/root transitions.

Read diagnostics are captured once on first ReadFile, matching the runtime's
launch-time environment policy. Repeated mute-option parsing and duplicated
overlapped-read muting are removed. Read timing is sampled only when READLOG is
enabled. These changes reduce specific lookup and diagnostic work; race-loading
seconds, FPS, and audio starvation improvement remain device measurements.

## Device measurements and delivery

The existing UIKit status timer captures cumulative audio, file-cache, and PSO
counters every ten seconds. PSO capture stays on the render thread; audio uses a
try-lock. Captured values are written through the existing asynchronous log
queue. `NFSU2Runtime.log` records elapsed time, pipeline compilation time,
lookups/hits/probes, file reads/bytes/scans/hits, and audio Play/reissue/write
counts. No new file IO runs in the audio callback.
The existing GILLOG diagnostic defaults to 500 ms for this iOS session, respects
an explicit environment override, and emits at most 80 long-hold records. This
can correlate guest serialization with producer gaps before changing scheduling.

Public source and native synthetic tests live in `lyszq/NFSU2Recomp-iOS`.
Authenticated input, generated game C, full IPA, and detailed build evidence stay
in the existing private input/output lane. The protected environment still
requires the owner's review. v0.24 delivery evidence and installed user files
remain the rollback baseline.
