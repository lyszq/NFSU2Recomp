# iOS loading stall: frame-dependent clock

The v0.23 device log stops at 394 submitted frames. Four bounded CPU snapshots
place the main guest thread in a QPC polling helper during `MovieTexture`
initialization. This path measures five 200 ms intervals while calibrating time.
The full runtime supplies QPF = 1,000,000, so each interval requires 200,000 ticks.

The legacy desktop hybrid clock is advanced by `Present`. Without another
`Present`, its default interpolation is capped at 50 ms and its extra allowance
at 200 ms. A calibration begun after part of that allowance is spent cannot
measure another 200 ms. Its one-million-read fallback counts samples equal to
the INITIAL counter, rather than equal to the preceding sample. Once the counter
has advanced and then plateaued below the deadline, that fallback no longer
decrements. Under this condition the polling loop cannot finish.
Multimedia timer deadlines and the streaming worker use the same capped clock,
so their progress also suffers. Mutex samples show repeated successful ownership
and release, rather than a persistent mutex owner. No mutex behavior was changed.

On iOS, the full runtime now derives shared process-relative microseconds from
`CLOCK_MONOTONIC`. Atomic origin and maximum-elapsed sampling prevent a late
concurrent read from rewinding time. `Present` no longer advances or resets this
clock. QPC frequency remains 1 MHz; millisecond conversion, timer deadlines and
audio pacing keep the same units. Desktop hybrid-clock and frame-pacing behavior
are preserved. Prior file-import, Files sharing and Metal lease fixes remain.

The Win32 time basis follows the
[QPC interval-measurement contract](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).
This change does not skip movie initialization or fabricate completed loading.

An isolated private replay of the original x86 helper starts at 150,000 ticks
and then caps its counter at 250,000: after 20,000 calls it remains in the loop,
with the fallback guard untouched and a 100,000-tick delta below its threshold.
The same helper with continuous time returns after 101 calls at a 200,000-tick
delta. This is bounded original-code regression evidence, not full-game playback.

Synthetic native tests exercise the production clock helper: 200 ms deadlines
after prior elapsed time with no frame, 5/7 ms timer rearming for over two seconds,
unchanged polling, out-of-order samples and long elapsed intervals. Public tests
contain no original game input. Any original-function replay stays private.
Native compile/link and helper tests still require physical iPad follow-up to
establish that loading, later menus and racing work with the complete game.
