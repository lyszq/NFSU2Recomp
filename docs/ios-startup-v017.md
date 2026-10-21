# v0.17 resource contracts and typed USER32 objects

The user directly confirmed v0.16 entry parity at LoadIconA and the live hover
test. Touch was not separately reported. The active preview input code and
the labeled thread-local (320,180) entry fixture remain separate.

## The missing executable icon

The authenticated executable has RT_GROUP_ICON under the string name
IDI_ICON1, with a referenced RT_ICON. It has no numeric group-icon32512.
The observed call is LoadIconA(00400000, MAKEINTRESOURCE(32512)); its nonzero
module argument requests an executable resource, not a default system icon.

A local Windows probe loaded this exact image as DATAFILE/IMAGE_RESOURCE,
without running its code. The numeric LoadIconA returned NULL/LastError1813
under flags2,32,34. The named IDI_ICON1 load succeeded under all three flags,
confirming that resource access worked. FindResourceW(type14,numeric32512)
independently returned a missing-name result. These APIs have distinct error
behavior; the LoadIconA contract uses its measured1813, not the FindResource
error. Evidence JSON remains ignored/private. This is a current Windows
capture, not a historical XP host capture.

`guest_resources` checks the loaded image's resource span, bounded directory
tables, names, named/ID partitions, ordering and directory ancestor aliases
before proving numeric absence. Missing icon then completes as NULL/1813,
with full stack/TEB preflight and preserved non-result CPU state. Present icons,
other IDs/modules and malformed readable metadata remain unsupported. Unmapped
in-span reads fault atomically. No icon bytes or generated game code are copied
into authored sources. The independent oracle derives absence from pefile's
original authenticated inventory rather than using the native parser.

## A shared system cursor object

Only LoadCursorA(NULL,IDC_ARROW32512) is supported. Local Windows probes showed
a successful shared cursor load with preserved LastError. The guest models this
as a process-scoped CURSOR/SYSTEM_SHARED descriptor in an eight-slot registry.
The opaque guest handle is a declared virtual identity (00b10001+slot), not a
copied Windows pointer. Repeated loads resolve the same typed object; consumers
must validate table membership and type. Unknown IDs/modules, invalid tables,
duplicates and capacity exhaustion stop without mutation. Cleanup clears the
registry. The descriptor represents cursor identity only; it does not claim
visible game cursor rendering or a created window.

Exact parity means original x86 instructions and native lifted execution agree
under this declared guest-object model. It does not mean host Windows and iOS
allocate identical numeric handles. The probe additionally compares every
USER32 object's handle/type/source/module/resource/shared fields and count,
and tests typed lookup. A thirteenth deliberately corrupted harness case
changes only the resource type, so correct registers/memory/counts alone cannot
hide an incorrect object. Existing exact trace, GPR/EFLAGS, heap metadata,
reference counts and image/TEB/stack/heap/process checks remain mandatory.

## Extended CPU query and real next boundary

The CPU model now stores EFLAGS.ID (bit21), and parity compares the
0x00200cd5 mask. The oracle's old hardcoded ID-bit clear at007646e5 masked the
game's early CPUID detection path; that workaround has been removed. The fresh
reference therefore observes CPUID leaves [1, 0, 1, 0, 1, 0x80000001, 1], including
the previously hidden early leaf1 query. CPUID80000001 at0072ccc3 still returns
four zero registers, consistent with the upstream profile's lack of extended
features. Other undeclared leaves still stop. Independent hook tests ensure
Unicorn does not execute its own host/default CPUID and preserve GPR/flags/FP/
XMM state outside instruction outputs.

## Explicit deterministic entry clock

The independent original-x86 rerun still reaches the same
KERNEL32!CreateToolhelp32Snapshot boundary after 191558 architectural
instructions, 217258 raw hooks, 10482 dispatches and 865 APIs. It contains one
RDTSC at 0x006de715 (7202581). Before this fixture, the oracle used host RDTSC
while native execution correctly stopped at the unsupported instruction; that
left the two sides with different clock behavior.

Both sides now opt into `deterministic_entry_tsc_v1` for this bounded startup
entry only. Its initial value is 1000000 and each read advances by 1000, so the
single event returns 1000000 and leaves the next value at 1001000. The ordered
IP/value word-FNV hash is 1459213057555500656. The startup harness checks the
next value, read count and hash, and its fourteenth negative case corrupts the
clock hash and must fail. Ordinary native RDTSC remains unsupported without
the explicit fixture. These fixed values make the comparison reproducible;
they do not claim to model real game timing or a real CPU clock.

Original x86 execution reaches KERNEL32!CreateToolhelp32Snapshot at0076e9fc,
targetf000008d, requesting flags2 (process snapshot), processID0. Reference:
191558 architectural instructions,217258 raw hooks,10482 dispatches,865 APIs,
depth12,14 critical sections and one TLS key. This path has1022 unique observed
transfer targets; generation allows1200 bounded bodies plus the existing leaf
regression (1201 registered functions). Every executed target must be lifted.
No unsupported instruction or missing target becomes a successful stub.

Process enumeration remains unsupported. RegisterClassA/CreateWindow have not
been reached or implemented by this milestone. No window, game boot, rendering,
audio or gameplay success is claimed. Native and physical tests must be recorded
separately in delivery evidence.

Contract references: [LoadIconA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadicona),
[LoadCursorA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadcursora),
[shared cursors](https://learn.microsoft.com/en-us/windows/win32/menurc/about-cursors).
