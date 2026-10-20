#!/bin/bash
# Run from the repository root. Uses no proprietary or generated game source.
set -euo pipefail
DEST="${1:?usage: tests/run_guest_tests.sh output-directory}"
mkdir -p "$DEST"
CC="${CC:-clang}"
FLAGS=(-O2 -std=gnu11 -Wall -Wextra -Werror -Iruntime -fno-strict-aliasing -pthread)
"$CC" "${FLAGS[@]}" runtime/guest_dispatch.c tests/guest_dispatch_test.c -o "$DEST/guest-dispatch-test"
"$DEST/guest-dispatch-test"
"$CC" "${FLAGS[@]}" runtime/guest_dispatch.c runtime/guest_execution.c runtime/guest_bootstrap.c   runtime/guest_memory.c tests/guest_execution_test.c -o "$DEST/guest-execution-test"
"$DEST/guest-execution-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c runtime/guest_heap.c tests/guest_heap_test.c -o "$DEST/guest-heap-test"
"$DEST/guest-heap-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c runtime/guest_critical.c tests/guest_critical_test.c -o "$DEST/guest-critical-test"
"$DEST/guest-critical-test"
"$CC" "${FLAGS[@]}" runtime/guest_dispatch.c runtime/guest_execution.c runtime/guest_windows.c runtime/guest_heap.c runtime/guest_critical.c runtime/guest_memory.c tests/guest_windows_test.c -o "$DEST/guest-windows-test"
"$DEST/guest-windows-test"
"$CC" "${FLAGS[@]}" -c runtime/dispatch.c -o "$DEST/desktop-dispatch.o"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c tests/guest_memory_test.c -o "$DEST/guest-memory-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c runtime/guest_pe.c tests/guest_pe_test.c -o "$DEST/guest-pe-test"
"$DEST/guest-pe-test"
"$DEST/guest-memory-test"
"$CC" "${FLAGS[@]}" runtime/guest_memory.c runtime/guest_dispatch.c ios/tests/cpu_flags_test.c \
  ios/NFSU2iOS/Native/GuestSmoke.c ios/tests/smoke_cli.c -o "$DEST/nfsu2-smoke"
"$DEST/nfsu2-smoke"
if [[ "$(uname -s)" == Darwin ]]; then
  "$CC" "${FLAGS[@]}" runtime/mem.c runtime/guest_memory.c \
    tests/guest_memory_desktop_test.c -o "$DEST/guest-memory-desktop-test"
  "$DEST/guest-memory-desktop-test"
fi
