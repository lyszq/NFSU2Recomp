#!/bin/bash
# PRIVATE build hosts only. Generation must authenticate the EXE first.
# Run from the source repository root; never upload input or generated C.
set -euo pipefail
DEST="${1:?usage: run_native_probe.sh output-directory authenticated-exe}"
EXE="${2:?authenticated executable path required}"
mkdir -p "$DEST"
echo "Native probe host: $(uname -s) $(uname -m)"
clang -O2 -std=gnu11 -Wall -Wextra -Werror -Wno-unused-label \
  -fno-strict-aliasing -pthread -DNFS_PRIVATE_PROBE=1 -DNFS_PRIVATE_STARTUP=1 -Iruntime \
  runtime/guest_memory.c runtime/guest_pe.c runtime/guest_dispatch.c \
  runtime/guest_execution.c runtime/guest_bootstrap.c runtime/guest_windows.c \
  runtime/guest_heap.c runtime/guest_critical.c runtime/guest_tls.c \
  ios/NFSU2iOS/Native/GuestImageProbe.c tests/guest_image_cli.c \
  gen/ios-private/lifted.c gen/ios-private/private_probe.c \
  gen/ios-private/startup_lifted.c gen/ios-private/startup_probe.c \
  -o "$DEST/private-lifted-test"
file "$DEST/private-lifted-test"
if [[ "$(uname -s)" == Darwin ]]; then
  clang -std=gnu11 -fsyntax-only -Iruntime -Igen/ios-private tests/boot.c
fi
"$DEST/private-lifted-test" "$EXE"
