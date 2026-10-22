# Complete runtime iOS build lane

The explicit private full-runtime lane ports the existing macOS runtime; it does
not use `guest_execution` to run the complete generated corpus. The bounded
startup lane and its independent x86 oracle remain available unchanged.

Generate locally only under ignored `gen/all`, or generate on the private runner:

```powershell
python tools/ios_private/generate_shards.py --exe out/private/SPEED2.EXE --shards 128
python tools/ios_private/configure_project.py --mode all
```

The generator authenticates the exact supported EXE, matches override addresses,
produces import argument metadata, and records hashes of generated files. The
all-mode overlay requires the complete manifest and compiles the legacy
dispatch/Win32/COM/genexec/overrides/Metal/audio stack with all 128 shards. It
excludes the bounded executor and weak Metal bridge. It preserves the app bundle
identity and keeps the diagnostic target as the default public project.

After committing and pushing authored changes, the existing authorized private
provisioning entry point accepts an explicit lane:

```powershell
python tools/ios_private/provision.py --mode full --dispatch --macos-runner macos-15-intel
```

The source is pinned to an exact pushed commit. Only the dedicated marked private
repository may download the authenticated game input. Generated code, IPA,
linker map, symbol inventory, build logs and provenance stay in that private run.
The ordinary public workflow never downloads game inputs. `--mode startup`
selects the previous startup workflow; no auto-selection switches a full build
back to a startup probe.

`verify_full_link.py` requires all 128 object files in the link map and strong
symbols owned by the actual backend objects. It rejects weak renderer readiness,
wrong object ownership, missing entry points, and unresolved guest symbols. It
records the binary, link-map, symbol-list and generation-manifest hashes. System
framework dynamic imports remain visible in the evidence.

An all-shard link establishes compilation and linkage only. First game frame,
menu/race control, audible sound, background/resume, and iPad performance require
separate runtime/device evidence. Neither a clear frame nor a frame counter alone
establishes a real game scene. The session retains one coherent guest process;
it does not mix the bounded Win32 heap/handle/TLS state into the legacy runtime.
The existing runtime interprets small guest x86 thunks without CPU JIT.

If an app links successfully but a verifier defect rejects it, the private
`ios-full-reverify.yml` recovery lane checks the immutable original artifact.
Its original run/artifact IDs, artifact ZIP hash, compiled source and corrected
verifier source are explicitly pinned. `reverify_full_artifact.py` requires the
native reference tests and compile/link step to have passed and the sole failed
step to be the link verifier. It checks the original ZIP against GitHub metadata,
then repeats package, source and complete linkage checks without recompilation.
`verify_full_package.py --replay-run ID --replay-source SHA` additionally checks
successful private replay, its workflow pins, and byte identity with the original
IPA. Reports retain the original CI failure and separate successful verification;
they never relabel a failed build run as successful or change the compiled SHA.

The v0.21/build28 continuation adds thread-local legacy exit scopes, lifecycle
publication after successful worker creation, and preservation of an existing
verified executable when an invalid new selection fails. The renderer requires
usable base resources before readiness and decodes BC1/BC2/BC3 to BGRA8 only when
the device lacks native BC support. The capability selector is guarded at its
[iOS16.4 availability](https://developer.apple.com/documentation/metal/mtldevice/supportsbctexturecompression).
Compressed guest pitches stay unchanged; synthetic native vectors cover color,
alpha, row padding, edge and mip decoding independently of game assets.

`provision.py --mode full-simulator --dispatch --macos-runner macos-15-intel`
selects a separate PRIVATE all-shard simulator lane. It builds production app
sources and a separate XCUITest bundle; no autostart/test bypass enters the app.
The runner stages the same authenticated EXE and one explicitly named
missing-assets sentinel solely to expose the existing Start UI. Actual game
assets are intentionally absent. The test taps production Start, backgrounds and
reactivates the app, and checks UIKit responsiveness. A source-pinned native
log marker must be present at the actual generated-entry call site. XCUITest
execution has a 240-second external bound and the disposable app is terminated
after private log/screenshot capture. This is negative-input Simulator evidence,
not physical-device ARM64 validation, successful game boot or gameplay.

The post-v21 source continuation bounds the legacy child/timer guest memory
reservations in a shared pool of 495 pairs. TEBs occupy
`[0x01000000, 0x013de000)` and one-MiB stacks occupy
`[0x60100000, 0x7f000000)`, outside the image, heap, COM buffer padding and
primary stack. Suspended workers reserve before publication; failed starts
roll back. Completed workers unregister their CPU before releasing their pair;
reused TEB/TLS and stack contents are cleared. This is a memory reservation
limit, separate from the unchanged cumulative 511-object legacy handle table.
It does not establish that the game reaches either limit.
Idle timers poll process exit without holding runtime locks. Infinite mutex
waits observe exit without jumping, then release their object lock and restore
the guest lock before unwinding through their own exit scope.

The renderer also re-arms pending work when `nextDrawable` temporarily returns
nil. The next render tick can retry the ready frame instead of leaving it
stranded until another guest Present replaces it after its timeout. These
source changes require a new private full build before they appear in an IPA;
the delivered v0.21/build28 artifact retains its original compiled source pin.
