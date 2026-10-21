# v0.15 startup contracts

The user confirmed the v0.14.0 entry probe on a physical iPad (build 21), with
exact 138712-instruction / 7866-call / 581-API parity and a USER32.dll!GetCursorPos
stop at IP 005bf7a7. Exact architectural trace, GPR/EFLAGS, registered functions
(601), native critical sections (14), TLS keys (1), and memory hashes all matched
the independent reference; leaf regression passed. The standalone CPU/memory
button and device model/OS were not separately reported in that message. The new
contracts below advance execution while preserving exact independent reference parity.

## Thread-safe atomic cursor state

The guest cursor subsystem (`guest_cursor.c` / `guest_cursor.h`) manages pointer
coordinates and device availability across concurrent threads without locks.
Coordinates are packed into a single C11 `_Atomic uint64_t` where the high 32
bits store `int32_t x` and the low 32 bits store `int32_t y`. This bit-packing
guarantees atomic 64-bit load/store operations, preventing torn reads between
the host UI/rendering loop and the guest CPU execution thread.

Cursor state flags track runtime conditions:
- `GUEST_CURSOR_FLAG_AVAILABLE`: active host touch or hover device tracked.
- `GUEST_CURSOR_FLAG_VISIBLE`: Win32 display count is greater than or equal to zero.
- `GUEST_CURSOR_FLAG_DOWN`: primary touch or mouse button is actively depressed.
- `GUEST_CURSOR_FLAG_SYNTHETIC`: deterministic test injection actively engaged.

Coordinate translation between host view space and guest game space supports
`GUEST_CURSOR_SCALE_FIT` (aspect-ratio preservation with centered letterbox or
pillarbox margins) and `GUEST_CURSOR_SCALE_STRETCH`. Coordinates outside the
rendered game area are clamped to `[0, game_w - 1]` and `[0, game_h - 1]`.
Synthetic test injection (`guest_cursor_inject_synthetic` / `guest_cursor_clear_synthetic`)
is explicitly opt-in: while active, host ingress updates are suppressed to ensure
hermetic test execution.

## Cursor query contracts

Win32 cursor imports implement the standard stdcall ABI:

- `GetCursorPos(LPPOINT lpPoint)`: 1 pointer argument, callee pops 4 bytes (8-byte
  stack frame with return address). If `lpPoint` is NULL, Windows reports
  `ERROR_NOACCESS` (998) at TEB LastError offset `0x34` and returns `FALSE` (`EAX = 0`).
  If `lpPoint` is valid, it writes the 8-byte `POINT` structure (`x`, `y` signed 32-bit
  integers) from the atomic snapshot, returns `TRUE` (`EAX = 1`), and preserves LastError.
  The handler preflights stack frame readability and destination write permissions;
  unmapped or invalid addresses trigger atomic memory faults without state mutation.
- `SetCursorPos(int x, int y)`: 2 arguments, callee pops 8 bytes (12-byte stack frame).
  Updates the atomic coordinates when synthetic override is inactive and returns `TRUE`.
- `ShowCursor(BOOL bShow)`: 1 argument, callee pops 4 bytes (8-byte stack frame).
  Atomically increments (if `bShow != 0`) or decrements (if `bShow == 0`) the display
  counter `g_display_count`, updates `GUEST_CURSOR_FLAG_VISIBLE`, and returns the
  resulting display count in `EAX`.

## Client rectangle query

The authentic startup sequence issues `USER32.dll!GetClientRect` with `HWND = NULL`.
Implemented in `runtime/guest_windows.c`, this query matches the existing `GetWindowRect`
contract:
- Stdcall ABI: 2 arguments (`HWND hWnd, LPRECT lpRect`), callee pops 8 bytes
  (12-byte stack frame).
- NULL HWND behavior: returns `FALSE` (`EAX = 0`) and sets `LastError = 1400`
  (`ERROR_INVALID_WINDOW_HANDLE`) at TEB offset `0x34`.
- The destination `RECT` is never read or written, tolerating poisoned or unmapped
  pointers without memory faults.
- Nonzero window handles remain strictly unsupported because no guest window has
  been created or bound. No fake window geometry or success results are fabricated.

## Input bridge sanitization

In earlier revisions, `ios/NFSU2iOS/Native/NFSU2InputBridge.c` defined
`NFSU2_KEYBOARD_BUFFER_GUEST_ADDR` at `0x00870990u` and mutated 256 bytes in guest
virtual memory during key events, `nfsu2_input_clear_all`, and guest memory sync.

In `SPEED2.EXE`, `0x00870990` is an internal game window handle and system state
structure (HWND storage), not a raw DirectInput buffer. Writing keyboard states
over this address corrupted the game window handle during early initialization.
Authentic x86 execution queries DirectInput keyboard state via
`IDirectInputDevice8::GetDeviceState`, which is serviced through `metal_fill_keyboard`.
All direct memory writes to `0x00870990` have been removed. `nfsu2_input_sync_guest_memory`
remains as a documented no-op for ABI compatibility.

## UIKit pointer and touch interaction

Live pointer interaction is integrated into `ios/NFSU2iOS/GameMetalView.swift`
(`NFSU2MetalRenderUIView`):
- A `UIHoverGestureRecognizer` targets `handleHover(_:)` to track iPadOS trackpad
  and mouse pointer motion and hover state transitions, updating coordinates via
  `nfsu2_input_set_cursor` and toggling availability via `nfsu2_input_set_cursor_available`.
- Multi-touch methods (`touchesBegan`, `touchesMoved`, `touchesEnded`, `touchesCancelled`)
  track primary touch coordinates and depress state (`is_down`), providing direct touch
  input into the atomic cursor snapshot.
- Dynamic viewport synchronization: `layoutSubviews` queries `metal_game_size` and
  passes the current view bounds and game resolution to `nfsu2_input_set_viewport`,
  maintaining accurate letterbox/pillarbox transformation ratios across orientation
  and window sizing changes.
- Background transitions (`applicationDidEnterBackground`) clear all pressed keys
  and mark cursor availability false.

## New independent reference frontier

With these declared contracts, authenticated original x86 execution advances from
the `GetCursorPos` stop to `USER32.dll!GetSystemMetrics`:
- **138,816** architectural instructions
- **151,595** raw Unicorn callbacks
- **7,872** CALL/entry dispatches
- **586** implemented API invocations
- Maximum call depth remains **12**
- **14** native critical sections and **1** TLS slot

The new frontier stops at `USER32.dll!GetSystemMetrics` (argument 1, metric index query),
which remains unsupported. Every generated native comparison is exact: instruction trace,
GPRs, EFLAGS, heap metadata, process references, and memory hashes (image, TEB, stack,
heap, process) match the independent reference execution.

Unit tests (`tests/guest_cursor_test.c`, `tests/guest_window_query_test.c`,
`tests/input_bridge_test.c`, `tools/ios_private/test_cursor_oracle.py`, and
`tools/ios_private/test_window_oracle.py`) exercise valid coordinate writes, NULL pointer
fault paths, LastError propagation, register preservation, stack cleanup, and viewport
aspect scaling. As with earlier milestones, this advance does not claim game boot,
rendering, audio, or gameplay.

Contract references: [GetCursorPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getcursorpos),
[SetCursorPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setcursorpos),
[ShowCursor](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showcursor),
[GetClientRect](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclientrect),
[GetSystemMetrics](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics),
[UIHoverGestureRecognizer](https://developer.apple.com/documentation/uikit/uihovergesturerecognizer).
