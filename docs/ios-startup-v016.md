# v0.16: live preview input and a declared startup fixture

The v0.15 package reached GetSystemMetrics with a successful headless (0,0)
cursor on both native and oracle sides. That established agreement for that
model; it did not establish real UIKit input. The active ContentView still used
MetalPreview, while touch handlers had been added to an unused game view.

## Live input

MetalPreview now installs touch/hover handling on its actual MTKView. Primary
touch identity survives secondary-touch end events; cancellation, view removal,
loss of activation and hover exit release availability and button state. A
native readback panel displays current coordinates/down state or unavailable.
The existing Metal triangle remains a device test, not a game renderer.

The preview maps UIKit points to an explicitly defined 1280x720 virtual guest
desktop using aspect-fit/clamping. This is a diagnostic input coordinate space;
no guest HWND, ScreenToClient conversion or physical Windows desktop is claimed.
Those require the future window lifecycle. Mouse/keyboard/gamepad gameplay has
not been validated by merely compiling this preview.

The cursor starts unavailable. GetCursorPos and SetCursorPos cannot manufacture
a live initialized pointer. Frame and complete output preflight precede writes;
an unsupported available-state query leaves guest registers/memory untouched.
NULL GetCursorPos retains its bounded LastError contract. One mutex protects
coordinates, flags, viewport and relative mouse state coherently. We do not
claim lock-free behavior. DirectInput writes exactly 16 or 20 bytes according
to the requested state layout, preserves trailing bytes and rejects short or
intermediate buffer lengths without consuming movement.

## Reproducible entry input

The entry probe explicitly injects fixture (320,180), profile
`deterministic_cursor_fixture_v1`, on its calling runtime thread only. The UI
and returned diagnostic label this input as synthetic. Actual UIKit ingress
continues updating the separate live snapshot. Other threads never see the
fixture. The harness clears it on both success and failure. Synthetic harness
tests verify that cleanup and preservation of preexisting live state, as well
as all twelve deliberately corrupted trace/count/memory cases.

The independent Unicorn model requires explicitly supplied coordinates,
availability and profile; it no longer silently invents a successful (0,0).
Exact native/oracle comparison proves execution under this declared fixture;
it is not physical touch/hover QA. Device tests must report these separately.

## Bounded next API and frontier

GetSystemMetrics handles only SM_SWAPBUTTON (23), returning zero because the
guest input mapping explicitly uses button0 as the primary/left button. It
preserves LastError and all CPU state beyond stdcall EAX/EIP/ESP. All other
indices remain unsupported; screen dimensions are not fabricated.

Original x86 reference under the declared fixture reaches LoadIconA at
0077fc1a, target f000000d: hInstance00400000, resource ID7f00. Counts are
180671 architectural instructions, 206298 raw callbacks, 9511 dispatches,
745 API calls and maximum depth12. Fourteen critical sections and one TLS key
remain. The bounded generator now allows800 bodies plus the existing leaf
regression (801 registered functions), because715 unique transfer targets
occur in the new observed prefix. It still rejects any unlifted observed target.
No mock resource handles or unverified LoadIconA/LoadCursorA success are used.

GetClientRect(NULL) was separately measured on local Windows during this
takeover: FALSE, LastError1400, four poisoned RECT words preserved. This
supports the existing null-window contract; it does not create a guest window.

Unintegrated previous input/thread drafts and oracle changes were preserved
byte-for-byte under ignored out/private/takeover-2026-10-21. They are not linked
or published. Audio, VFS and texture planning from those reports does not imply
working runtime integration. No game boot, audio, game rendering or gameplay
claim is made by this milestone.

References: [GetSystemMetrics](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics),
[GetCursorPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getcursorpos).
