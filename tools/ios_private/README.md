# Private iOS native function build

This template is deliberately outside `.github/workflows`. The public workflow
builds only infrastructure and synthetic tests; it never receives the game EXE
or generates game-derived C. Keep the separate build repository private.

The first real function is the existing upstream `sub_0048b1e0` test target.
It is a seven-instruction cdecl leaf with a caller-clean stack and a deterministic
32-bit result. The generator authenticates the exact supported EXE, lifts that
function using the existing `tools/lift.py`, and builds 48 reference vectors by
running its original x86 instructions in Unicorn **on the build host**. Native
C then must match all general registers, defined arithmetic flags, DF, return
address and stack bytes. Unicorn and x86 machine code are not bundled into iOS.
There is no dummy implementation if private generation fails.

## Provision on Windows

Requires Python 3 and the user's existing GitHub sign-in through Git Credential
Manager. No token is printed, saved to a file, or put into a command argument.
First commit/push the infrastructure on the existing public feature branch.
From the source repository, run:

```powershell
python tools/ios_private/provision.py --create --exe "C:\path\to\SPEED2.EXE" --dispatch
```

The script creates `lyszq/NFSU2Recomp-ios-private`, verifies its private visibility
and purpose marker, and pins the workflow to the exact pushed source commit.
Only the workflow and a README are committed in the control repository.
The authenticated EXE is uploaded as a **private release asset**, not into Git.
An existing asset is reused only with the exact matching SHA-256 digest.
The source repository's `gen/` and `out/` directories remain ignored.

The private workflow rechecks visibility before fetching the input. It generates
on a temporary macOS runner, runs the native function harness twice, builds a
native ARM64 iOS 0.4.1 IPA, and checks that both the actual `sub_0048b1e0` symbol
and its harness are live in the link map. Its seven-day private artifact contains
only the unsigned IPA, hash/provenance metadata and test diagnostics; no raw EXE
or generated C source is uploaded as an artifact. Temporary input and generated
source are removed during cleanup. The private release input remains available
for repeat builds until the owner deletes it.

To update the pinned source and rerun without reuploading the EXE:

```powershell
python tools/ios_private/provision.py --dispatch
```

## Device check

Sign the private 0.4.1 IPA with the existing identity and upgrade the app without
deleting it. The bundle ID and verified-EXE save location stay the same. Run
**LOAD VERIFIED GAME IMAGE**; the private build maps the actual authenticated
image, executes the statically recompiled leaf against all 48 reference cases,
and releases the temporary runtime mapping. Share the full diagnostic.

Native host success and a linked ARM64 binary are separate from an iPad PASS.
This milestone executes one isolated actual game function. It does not invoke
the game entry point, dispatch the complete engine, bind imports, or render a
game scene. Full boot, renderer, audio and input integration remain future work.


## Entry probe (0.5.1)

The physical iPad v0.4.1 leaf regression was confirmed on 20 October 2026.
The new build also generates a bounded authentic entry call graph, routes both
direct and indirect guest calls through shared native dispatch, and compares
the initial entry prefix with an independent original-x86 reference.

The expected boundary is `KERNEL32.dll!GetVersionExA`, after 40 original
instructions. No API result is supplied or fabricated. An exact match reports
`VERIFIED ENTRY STOP` with the missing API, instruction/call counts and state
verification. This proves the real entry prefix up to that boundary; it does not
mean CRT initialization, game startup or rendering have completed. Press the
same LOAD VERIFIED GAME IMAGE button and share the full diagnostic.

The private artifact name stays stable for repeat builds. Only IPA, provenance
and diagnostics are retained there; entry-generated C and the EXE stay out of Git
and public artifacts. The native runner is bounded and uses no JIT or x86
interpreter on iOS. Unicorn remains a build-host-only reference engine.


## Windows contract / heap probe (0.6.1)

The latest private build retains all 48 real-leaf reference cases, then runs
actual lifted entry functions with the shared Windows compatibility bridge.
It passes version and module queries and creates a real guest heap; four API
invocations complete before the explicit InitializeCriticalSection boundary.
The original-x86 reference uses the same documented guest compatibility policy,
implemented independently in Python. The expected native stop is 154 instructions,
15 calls and depth 5, with exact trace/register/image/TEB/stack/heap comparisons.
This validates translation under the declared guest contracts; it is not a
comparison against a complete Windows installation or a successful game boot.

Use the latest private IPA, version 0.6.1/build 9, with the same signing identity
and bundle ID. Upgrade without deleting the existing app. One run of LOAD
VERIFIED GAME IMAGE runs the retained real-leaf regression and new startup probe
together. CPU/memory tests remain separately available. Earlier 0.5.1 build
instructions above describe that historical boundary, not the latest probe.
The current missing API is InitializeCriticalSection. Gameplay, renderer,
audio and input remain unimplemented. Device confirmation is still pending.
