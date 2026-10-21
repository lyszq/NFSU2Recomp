#!/usr/bin/env python3
"""Explicit deterministic clock fixture for three bounded KERNEL32 APIs."""
from __future__ import annotations

import struct
from typing import Any

from window_oracle import _memory_fault, _range_has_permissions


CLOCK_PROFILE = "deterministic_clock_fixture_v1"
KERNEL32 = "kernel32.dll"
IMPORT_BASE = 0xF0000000
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
INT64_MAX = 0x7FFFFFFFFFFFFFFF

_CLOCK_FIELDS = frozenset((
    "mode", "frequency", "next", "increment", "query_count",
    "sample_count", "trace_hash",
))
_CLOCK_APIS = {
    "QueryPerformanceFrequency": (1, 1),
    "QueryPerformanceCounter": (2, 1),
    "GetTickCount": (3, 0),
}


def _uint(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _clock_fault(state: dict[str, Any], name: str, reason: str) -> None:
    call_ip = state.get("last_ip", 0)
    if type(call_ip) is not int or not 0 <= call_ip <= UINT32_MAX:
        call_ip = 0
    state["status"] = "GUEST_STOP_API_STATE"
    state["target"] = 0
    state["api_state_fault"] = {
        "api": name,
        "address": call_ip,
        "reason": reason,
    }


def _valid_clock(clock: object) -> bool:
    if type(clock) is not dict or set(clock) != _CLOCK_FIELDS:
        return False
    return (
        type(clock["mode"]) is int and clock["mode"] == 1
        and type(clock["frequency"]) is int
        and 1 <= clock["frequency"] <= INT64_MAX
        and _uint(clock["next"], INT64_MAX)
        and type(clock["increment"]) is int
        and 1 <= clock["increment"] <= INT64_MAX
        and _uint(clock["query_count"], UINT64_MAX)
        and _uint(clock["sample_count"], UINT64_MAX)
        and clock["sample_count"] <= clock["query_count"]
        and _uint(clock["trace_hash"], UINT64_MAX)
    )


def _fold_word(hash_value: int, word: int) -> int:
    return ((hash_value ^ word) * FNV_PRIME) & UINT64_MAX


def _clock_import_fault(state: dict[str, Any], access: str,
                        address: int, size: int) -> None:
    _memory_fault(state, access, address, size)


def handle_clock_import(engine: Any, registers: Any, unicorn_module: Any,
                        import_row: dict[str, Any],
                        mapped_ranges: list[tuple[int, int]],
                        state: dict[str, Any]) -> bool:
    """Handle only explicitly configured QPF, QPC, and GetTickCount calls.

    Each supported API first snapshots its entire stdcall frame. QPF/QPC then
    preflight the full eight-byte output before any guest or clock state is
    changed. Missing or malformed clock state stops explicitly; the oracle
    never reads the host clock or invents a successful default.
    """
    library = import_row.get("library", "")
    name = import_row.get("name")
    if (not isinstance(library, str) or library.casefold() != KERNEL32 or
            name not in _CLOCK_APIS):
        return False

    try:
        import_index = import_row.get("index")
        if (type(import_index) is not int or
                not 0 <= import_index <= 0x0FFFFFFF):
            return False
    except (AttributeError, TypeError):
        return False

    opcode, argument_count = _CLOCK_APIS[name]
    frame_size = 4 * (argument_count + 1)
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & UINT32_MAX
    if not _range_has_permissions(
            engine, esp, frame_size, unicorn_module.UC_PROT_READ,
            mapped_ranges):
        _clock_import_fault(state, "read", esp, frame_size)
        return False

    # Keep the complete stdcall frame before any output can alias it.
    frame = bytes(engine.mem_read(esp, frame_size))
    return_address = struct.unpack_from("<I", frame, 0)[0]
    arguments = list(struct.unpack_from(
        "<" + "I" * argument_count, frame, 4)) if argument_count else []
    output_address = arguments[0] if argument_count else None

    if output_address is not None:
        if output_address == 0 or not _range_has_permissions(
                engine, output_address, 8, unicorn_module.UC_PROT_WRITE,
                mapped_ranges):
            _clock_import_fault(state, "write", output_address, 8)
            return False

    clock = state.get("clock")
    if not _valid_clock(clock):
        _clock_fault(state, name, "unconfigured_clock_profile")
        return False

    call_ip = state.get("last_ip")
    if type(call_ip) is not int or not 0 <= call_ip <= UINT32_MAX:
        _clock_fault(state, name, "invalid_call_ip")
        return False
    if "api_calls" in state and type(state["api_calls"]) is not list:
        _clock_fault(state, name, "invalid_api_log")
        return False

    query_count = clock["query_count"]
    sample_count = clock["sample_count"]
    next_value = clock["next"]
    frequency = clock["frequency"]
    increment = clock["increment"]
    if query_count == UINT64_MAX:
        _clock_fault(state, name, "query_count_overflow")
        return False

    if name == "QueryPerformanceFrequency":
        returned_value = frequency
        result = 1
        next_after = next_value
        sample_after = sample_count
    else:
        if sample_count == UINT64_MAX:
            _clock_fault(state, name, "sample_count_overflow")
            return False
        next_after = next_value + increment
        if next_after > INT64_MAX:
            _clock_fault(state, name, "counter_overflow")
            return False
        if name == "QueryPerformanceCounter":
            returned_value = next_value
            result = 1
        else:
            returned_value = ((next_value * 1000) // frequency) & UINT32_MAX
            result = returned_value
        sample_after = sample_count + 1

    hash_value = FNV_OFFSET if query_count == 0 else clock["trace_hash"]
    hash_value = _fold_word(hash_value, opcode)
    hash_value = _fold_word(hash_value, returned_value)

    # All guest ranges and clock arithmetic are now preflighted.
    if output_address is not None:
        engine.mem_write(output_address, struct.pack("<Q", returned_value))

    clock["query_count"] = query_count + 1
    clock["sample_count"] = sample_after
    clock["next"] = next_after
    clock["trace_hash"] = hash_value
    state.setdefault("api_calls", []).append({
        "library": library,
        "name": name,
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": call_ip,
        "esp_before": esp,
        "argument_count": argument_count,
        "return_address": return_address,
        "arguments": arguments,
        "result": result,
        "profile": CLOCK_PROFILE,
        "clock_opcode": opcode,
        "clock_value": returned_value,
        "clock_next_after": next_after,
        "clock_query_count": query_count + 1,
        "clock_sample_count": sample_after,
        "trace_hash": hash_value,
        "esp_after": (esp + frame_size) & UINT32_MAX,
    })
    engine.reg_write(registers.UC_X86_REG_EAX, result & UINT32_MAX)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP,
                     (esp + frame_size) & UINT32_MAX)
    state["resume"] = True
    return True


__all__ = ["CLOCK_PROFILE", "FNV_OFFSET", "FNV_PRIME", "handle_clock_import"]
