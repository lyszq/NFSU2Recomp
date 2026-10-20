#!/bin/bash
# Run from the repository root. Uses no proprietary or generated game source.
set -euo pipefail
DEST="${1:?usage: tests/run_guest_tests.sh output-directory}"
mkdir -p "$DEST"
CC="${CC:-clang}"
FLAGS=(-O2 -std=gnu11 -Wall -Wextra -Werror -Iruntime -fno-strict-aliasing -pthread)
"$CC" "${FLAGS[@]}" runtime/guest_memory.c tests/guest_memory_test.c -o "$DEST/guest-memory-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c runtime/guest_pe.c tests/guest_pe_test.c -o "$DEST/guest-pe-test"
"$DEST/guest-pe-test"
"$DEST/guest-memory-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c ios/tests/cpu_flags_test.c \
  ios/NFSU2iOS/Native/GuestSmoke.c ios/tests/smoke_cli.c -o "$DEST/nfsu2-smoke"
"$DEST/nfsu2-smoke"
if [[ "$(uname -s)" == Darwin ]]; then
  "$CC" "${FLAGS[@]}" runtime/mem.c runtime/guest_memory.c \
    tests/guest_memory_desktop_test.c -o "$DEST/guest-memory-desktop-test"
  "$DEST/guest-memory-desktop-test"
fi
