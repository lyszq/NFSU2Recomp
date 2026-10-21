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
