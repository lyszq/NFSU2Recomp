# NFSU2 iOS Stage 2 — native guest runtime smoke test

This stage deliberately validates small, authentic pieces of the upstream
macOS runtime on iPhone/iPad **without running NFSU2**.

## Changes from Stage 1

- `Native/GuestSmoke.c` includes the **original** [`runtime/cpu.h`](../../runtime/cpu.h) and executes
  its x86 EFLAGS macros against a real `CPU` struct, including signed overflow,
  carry, zero, parity and borrow; verifies x87/MMX/XMM **storage**.
- Probes a 4 GiB **virtual** guest mapping using `mmap(PROT_NONE)` (NOT 4 GiB RAM),
  commits three host-sized pages with `mprotect`, reads/writes 32-bit guest
  addresses in the PE/heap/high ranges, then unmaps everything.
- A SwiftUI test button displays an explicit PASS or FAIL (with errno on VM failure).
  Tests run on a worker queue, not the UI thread.
- The same native test executable runs in CI on macOS before the iOS target is
  built, including all C sources, helping catch upstream header changes.
- The working Metal triangle, SHA-256/size validator, and locally saved EXE
  are unchanged.

## What this stage does **not** do

- `runtime/mem.c` is not linked yet. It includes macOS debug signal handling;
  the isolated iOS probe uses its 4 GiB offset model, not the full manager.
- No generated `gen/all/shard_*.c` is included, no game instructions executed,
  no Direct3D-to-Metal game rendering, audio, menus or races.
- The ISO/PC game files are not uploaded to GitHub.
- Success on a macOS runner does not guarantee iOS mmap permissions; confirm
  with the button on your iPad before treating the address-space test as passed.

## Update on a Windows machine

Use the one-click v0.2 update kit supplied with this revision. It applies
only the `ios/` and workflow changes to `feat/ios-metal-bootstrap`, commits,
and pushes them to the user's own fork.

## iOS install

GitHub Actions builds an **unsigned** IPA. It needs normal device signing
before installation. App bundle ID is unchanged (`dev.lyszq.nfsu2ios`).

## Next milestone

Once both native tests pass on iPad, refactor the guest memory manager into a
portable module and implement an iOS game-boot entry. Generate C from a supported
SPEED2.EXE **privately**; never commit generated game code to a public repo.
