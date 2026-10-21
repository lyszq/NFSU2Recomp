# v0.14 startup contracts

The user confirmed the v0.13.1 entry probe on a physical iPad, with exact
117395-instruction/6781-call parity and a RegOpenKeyA stop. The standalone
CPU/memory button and device model/OS were not separately reported in that
message. The new contracts below retain exact independent reference checks.

## Registry namespace

The guest has five predefined root handles over an explicitly empty, read-only
registry profile. RegOpenKeyA returns the same root for a NULL/empty subkey,
ERROR_FILE_NOT_FOUND for a nonempty subkey, and ERROR_INVALID_HANDLE for an
unknown handle. Failures zero the output handle; LastError is preserved.
There are no fabricated Direct3D settings or host-registry reads.

The observed startup asks twice for HKLM\Software\Microsoft\Direct3D. Both
queries take the missing-key error path. Before implementing that contract,
direct Windows advapi32 calls on a synthetic nonexistent key verified result 2,
a null output handle and preserved LastError; an empty subkey returned the root.
The handler snapshots its frame, scans at most4096 bytes before mutation, and
checks the complete output range. Overlong strings remain explicit stops.

## CPU capabilities

The next observed IsProcessorFeaturePresent argument is7,
PF_3DNOW_INSTRUCTIONS_AVAILABLE. The portable guest does not advertise 3DNow:
some upstream translations omit its refinement instructions. This query returns
FALSE with the documented stdcall ABI and preserves LastError. Other feature
numbers remain unsupported; host ARM/Intel capabilities are not substituted.

## Invalid window query

The authentic next GetWindowRect call uses HWND=NULL. A direct Windows user32
probe returned FALSE/LastError1400 and left all four poisoned RECT words intact;
a NULL RECT pointer produced the same error. The guest implements this exact
failure, never reads/writes the RECT, and preflights the LastError DWORD before
mutation. Nonzero window handles remain unsupported because no guest window
has been created or bound. No success result or window dimensions are invented.

## New independent reference frontier

With these declared contracts, authenticated original x86 execution reaches
USER32.dll!GetCursorPos after138711 architectural instructions,151490 raw
Unicorn callbacks,7865 CALL/entry dispatches and580 implemented API invocations.
Maximum depth remains12. Every generated native comparison is exact.

The current cursor query is intentionally unsupported. Actual cursor/input
coordinates require a real platform input source and guest input lifecycle;
the existing weak frontend bridges are not proof of that integration. This
milestone does not claim game boot, rendering, audio or gameplay.

Synthetic native and independent Unicorn tests cover the new contracts,
unsupported cases, CPU/flags preservation, aliases, permissions and range
overflow. The private workflow tests native execution twice per host and
checks that the actual registry handler is present in the ARM64 link map.

Contract references: [RegOpenKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeya),
[IsProcessorFeaturePresent](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent),
[GetWindowRect](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowrect).
