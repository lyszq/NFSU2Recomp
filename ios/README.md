# NFSU2 iOS: Stage 1 native bootstrap

An iOS 16+ SwiftUI / UIKit + Metal application scaffold for experimenting with an eventual native Apple Silicon port of [TalhaMudo/NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp).

## What works in this stage

- Native iPhone/iPad app, compiling for arm64 on GitHub's macOS runner.
- Real Metal pipeline and shader drawn in an `MTKView` (graphics capability check).
- iOS Files picker for the *user's own* `SPEED2.EXE`.
- File-size/SHA-256 verification against upstream's supported build; saves verified executable in the app sandbox.
- GitHub Actions produces an **unsigned** `.ipa` as a downloadable workflow artifact.

## What does **not** work

- **This is NOT a playable NFSU2 port.** It does not compile or run the upstream recompilation, convert its AppKit renderer, play audio, load game resources or handle gameplay input.
- It does not ship a game executable or game data. It cannot generate the game's lifted C without a legal copy of the supported PC release.
- IPA is unsigned. Installation requires legitimate personal signing/sideloading (e.g. signing it with an Apple development identity); an unsigned archive cannot simply be tapped to install.

## Build it without a Mac

1. Fork `TalhaMudo/NFSU2Recomp` into your GitHub account (via GitHub's **Fork** button).
2. Copy `ios/` and `.github/workflows/ios-bootstrap.yml` from this overlay into your fork and commit. On Windows, after cloning your fork, extract the overlay zip into its root, then `git add ios .github/workflows/ios-bootstrap.yml && git commit -m "Add iOS Metal bootstrap and unsigned IPA CI" && git push`.
3. Open **Actions > iOS bootstrap (unsigned IPA) > Run workflow**. The push also triggers it.
4. If green, open the completed run and download `NFSU2iOS-bootstrap-unsigned` from **Artifacts**. The ZIP contains `NFSU2iOS-bootstrap-unsigned.ipa`.

This step deliberately builds *only* a Metal proof-of-life. Game porting is a separate, substantial task.

## Planned engineering milestones

- Port the macOS app shell from `NSApplication`/`NSWindow` (AppKit) to iOS `UIApplication` / `UIView` / `CAMetalLayer` or `MTKView`.
- Extract the existing D3D9-to-Metal translator so it accepts an iOS `CAMetalLayer` and doesn't depend on Cocoa window/event APIs.
- Adapt audio from macOS CoreAudio / AudioQueue to supported iOS audio session and render lifecycle (`AVAudioSession`).
- Review x86 32-bit guest address-space reservation, 64-bit pointers, signal/exception handling, and W^X restrictions on iOS.
- Adapt Win32 shims and file paths to sandbox-compatible paths, then implement keyboard/controller/touch input.
- Generate translated C locally **from the user's game** (never commit it) and build testable subsets of the portable runtime; integrate the game loop only after unit/runtime checks.
- Once the above passes on device, debug startup, menus, race loading, FMVs, audio and frame pacing.

This scaffold is additive to upstream. It avoids modifying macOS code until iOS platform boundaries have been identified.
