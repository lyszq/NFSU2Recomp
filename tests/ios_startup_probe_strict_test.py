#!/usr/bin/env python3
"""Render and execute startup_probe.c.in against a synthetic guest runtime."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "tools/ios_private/startup_probe.c.in"
FIXTURE = ROOT / "tests/ios_startup_probe_synthetic.c"
CC = os.environ.get("CC", "clang")
MASK64 = (1 << 64) - 1

IMAGE_BASE = 0x0075B000
IMAGE_SIZE = 0x4000
ENTRY = 0x0075BCC7
STEP_A = 0x0075BCC8
STEP_B = 0x0075BCC9
STEP_C = 0x0075BCCA
STEP_ALT = 0x0075BD00
TEB_BASE = 0x00C00000
PEB_BASE = 0x00C10000
STACK_LO = 0x7F000000
STACK_HI = 0x7FF00000
PROCESS_BASE = 0x00C20000
PROCESS_BYTES = 0x4000
HEAP_BASE = 0x20000000
HEAP_BLOCK = HEAP_BASE + 0x4000
STACK_START = STACK_HI - 0x1004
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211
# FNV fold of (STEP_B, 1000000) then (STEP_C, 1001000), matching the
# deterministic virtual counter configured in the rendered probe.
EXPECTED_TSC_HASH = 0xCD3BFA12B129556E


def fnv64(data: bytes) -> int:
    value = FNV_OFFSET
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & MASK64
    return value


def trace_hash(addresses: list[int]) -> int:
    value = FNV_OFFSET
    for address in addresses:
        value = ((value ^ address) * FNV_PRIME) & MASK64
    return value


def pack32(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset:offset + 4] = value.to_bytes(4, "little")


def expected_hashes() -> dict[str, int]:
    image = bytearray(IMAGE_SIZE)
    for index in range(5):
        pack32(image, 0x100 + 4 * index, 0xF0000000 + index)

    teb = bytearray(0x20000)
    for offset, value in [
        (0x00, 0xFFFFFFFF), (0x04, STACK_HI), (0x08, STACK_LO),
        (0x18, TEB_BASE), (0x20, 100), (0x24, 1),
        (0x2C, TEB_BASE + 0x1000), (0x30, PEB_BASE),
        (0x10000 + 0x08, IMAGE_BASE),
        (0x10000 + 0xA4, 5), (0x10000 + 0xA8, 1),
    ]:
        pack32(teb, offset, value)

    stack = (STEP_B).to_bytes(4, "little")
    process = bytearray(PROCESS_BYTES)
    command_line = b"C:\\NFSU2\\SPEED2.EXE\0"
    process[:len(command_line)] = command_line
    return {
        "EXPECTED_IMAGE_HASH": fnv64(image),
        "EXPECTED_TEB_HASH": fnv64(teb),
        "EXPECTED_STACK_HASH": fnv64(stack),
        "EXPECTED_HEAP_HASH": fnv64(bytes(16)),
        "EXPECTED_PROCESS_HASH": fnv64(process),
    }


def registers(eax: int, esp: int) -> str:
    values = [eax, 0, 0, 0, esp, 0, 0, 0]
    return ",".join(f"0x{value:08x}u" for value in values)


BASE_STACK_ESP = STACK_START + 32
EXTRA_API_ESP = BASE_STACK_ESP + 4


def substitutions() -> dict[str, str]:
    values = {
        "EXPECTED_GPRS": registers(HEAP_BLOCK, BASE_STACK_ESP),
        "EXPECTED_FLAGS": "0u",
        "EXPECTED_TARGET": "0xf0000002u",
        "EXPECTED_IP": f"0x{STEP_C:08x}u",
        "EXPECTED_STEPS": "3u",
        "EXPECTED_APIS": "2u",
        "EXPECTED_CRITICALS": "0u",
        "EXPECTED_TLS": "0u",
        "EXPECTED_TLS_THREADS": "0u",
        "EXPECTED_ENV_A_REFS": "0u",
        "EXPECTED_ENV_W_REFS": "0u",
        "EXPECTED_HEAPS": f"{{0u,{HEAP_BASE}u,16384u,1u}}",
        "EXPECTED_BLOCKS": f"{{0u,0u,{HEAP_BLOCK}u,16u,16u}}",
        "EXPECTED_CALLS": "4u",
        "EXPECTED_DEPTH": "1u",
        "EXPECTED_USER_OBJECT_COUNT": "1u",
        "EXPECTED_USER_OBJECTS": "{0x00b10001u,2u,2u,0u,32512u,1u}," + ",".join("{0u,0u,0u,0u,0u,0u}" for _ in range(7)),
        "EXPECTED_TSC_NEXT": "1002000",
        "EXPECTED_TSC_READS": "2",
        "EXPECTED_TSC_HASH": f"0x{EXPECTED_TSC_HASH:016x}",
        "EXPECTED_TRACE": str(trace_hash([STEP_A, STEP_B, STEP_C])),
        "HEAP_WINDOW_ADDRESS": f"0x{HEAP_BLOCK:08x}u",
        "HEAP_WINDOW_SIZE": "16u",
        "STACK_WINDOW_ADDRESS": f"0x{STACK_START:08x}u",
        "STACK_WINDOW_SIZE": "4u",
        "PROCESS_WINDOW_ADDRESS": f"0x{PROCESS_BASE:08x}u",
        "PROCESS_WINDOW_SIZE": f"{PROCESS_BYTES}u",
    }
    values.update({key: str(value) for key, value in expected_hashes().items()})
    return values


def render(base: dict[str, str], overrides: dict[str, str]) -> str:
    source = TEMPLATE.read_text(encoding="utf-8")
    if "@EXPECTED_DEPTH@" not in source:
        raise AssertionError("startup probe template must compare exact @EXPECTED_DEPTH@")
    selected = dict(base)
    selected.update(overrides)
    for key, value in selected.items():
        source = source.replace(f"@{key}@", value)
    unresolved = re.findall(r"@[A-Z_]+@", source)
    if unresolved:
        raise AssertionError(f"unresolved template placeholders: {sorted(set(unresolved))}")
    return source


def compile_case(directory: Path, name: str, base: dict[str, str],
                 overrides: dict[str, str]) -> Path:
    source = directory / f"{name}.c"
    executable = directory / name
    source.write_text(render(base, overrides), encoding="utf-8")
    command = [
        CC, "-O1", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
        f"-I{ROOT / 'runtime'}", str(FIXTURE), str(source),
        str(ROOT / "runtime/guest_execution.c"),
        str(ROOT / "runtime/guest_dispatch.c"),
        str(ROOT / "runtime/guest_bootstrap.c"),
        str(ROOT / "runtime/guest_memory.c"),
        str(ROOT / "runtime/guest_process.c"),
        str(ROOT / "runtime/guest_heap.c"),
        str(ROOT / "runtime/guest_cursor.c"),
        str(ROOT / "runtime/guest_user_objects.c"),
        "-lm",
        "-o", str(executable),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    return executable


def run_case(executable: Path, mode: str, should_pass: bool) -> str:
    result = subprocess.run([str(executable), mode], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.strip()
    if should_pass:
        if result.returncode != 0 or not output.startswith("VERIFIED ENTRY STOP"):
            raise AssertionError(
                f"{mode}: valid synthetic probe failed (rc={result.returncode})\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
    elif result.returncode == 0 or not output.startswith("FAIL | entry mismatch"):
        raise AssertionError(
            f"{mode}: corrupted probe was accepted (rc={result.returncode})\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return output


def main() -> int:
    if len(sys.argv) > 1:
        build_root = Path(sys.argv[1]).resolve()
        build_root.mkdir(parents=True, exist_ok=True)
    else:
        build_root = Path(tempfile.gettempdir())

    base = substitutions()
    gpr_after_extra_api = registers(1252, EXTRA_API_ESP)
    variants = {
        "baseline": {},
        "steps_only": {"EXPECTED_TRACE": str(trace_hash([STEP_A, STEP_ALT, STEP_B, STEP_C]))},
        "calls_only": {"EXPECTED_APIS": "3u", "EXPECTED_GPRS": gpr_after_extra_api},
        "apis_only": {"EXPECTED_CALLS": "5u", "EXPECTED_GPRS": gpr_after_extra_api},
        "heap_blocks_only": {"EXPECTED_GPRS": registers(0, BASE_STACK_ESP)},
        "depth_only": {"EXPECTED_CALLS": "5u"},
        "tsc_hash": {"EXPECTED_TSC_HASH": f"0x{EXPECTED_TSC_HASH ^ 1:016x}"},
    }
    with tempfile.TemporaryDirectory(prefix="ios-startup-probe-", dir=build_root) as tmp:
        directory = Path(tmp)
        binaries = {
            name: compile_case(directory, name, base, overrides)
            for name, overrides in variants.items()
        }

        run_case(binaries["baseline"], "valid", True)
        rejected = [
            ("trace", "baseline"), ("image", "baseline"), ("teb", "baseline"),
            ("stack", "baseline"), ("heap", "baseline"), ("process", "baseline"),
            ("target", "baseline"), ("user_objects", "baseline"), ("step_count", "steps_only"),
            ("call_count", "calls_only"), ("api_count", "apis_only"),
            ("block_count", "heap_blocks_only"), ("depth", "depth_only"),
            ("valid", "tsc_hash"),
        ]
        for mode, variant in rejected:
            run_case(binaries[variant], mode, False)

    print(f"PASS | rendered startup probe rejects {len(rejected)} synthetic regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
