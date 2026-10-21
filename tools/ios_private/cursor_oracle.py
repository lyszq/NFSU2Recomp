#!/usr/bin/env python3
"""Bounded synthetic GetCursorPos contract for the private startup oracle."""
from __future__ import annotations

import struct
from typing import Any

CURSOR_IMPORT_LIBRARY = "user32.dll"
CURSOR_IMPORT_NAME = "GetCursorPos"
CURSOR_PROFILE = "headless_default_cursor"
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
ERROR_NOACCESS = 998


def _range_is_mapped(address: int, size: int,
                     mapped_ranges: list[tuple[int, int]]) -> bool:
    if (address < 0 or size <= 0 or address > 0xFFFFFFFF or
            size > 0x100000000 - address):
        return False
    end = address + size
    return any(start <= address and end <= stop
               for start, stop in mapped_ranges)


def _range_has_permissions(engine: Any, address: int, size: int,
                           permissions: int,
                           mapped_ranges: list[tuple[int, int]]) -> bool:
    if not _range_is_mapped(address, size, mapped_ranges):
        return False
    end = address + size
    cursor = address
    for region_start, region_end, region_permissions in engine.mem_regions():
        region_end += 1
        if region_end <= cursor or region_start >= end:
            continue
        if (region_start > cursor or
                region_permissions & permissions != permissions):
            return False
        cursor = min(end, region_end)
        if cursor == end:
            return True
    return False


def _memory_fault(state: dict[str, Any], access: str, address: int,
                  size: int) -> None:
    fault = {"access": access, "address": int(address), "size": int(size)}
    state["status"] = "GUEST_STOP_MEMORY"
    state["target"] = int(address) & 0xFFFFFFFF
    state["memory_fault"] = fault


def _api_state_fault(state: dict[str, Any], address: int,
                     reason: str) -> None:
    target = int(address) & 0xFFFFFFFF
    state["status"] = "GUEST_STOP_API_STATE"
    state["target"] = target
    state["api_state_fault"] = {
        "api": CURSOR_IMPORT_NAME,
        "address": target,
        "reason": reason,
    }


def _cursor_query_import(engine: Any, registers: Any, unicorn_module: Any,
                         row: dict[str, Any],
                         mapped_ranges: list[tuple[int, int]],
                         state: dict[str, Any]) -> bool:
    """Model GetCursorPos(lpPoint) in a headless guest process.

    If lpPoint is NULL, Windows reports ERROR_NOACCESS (998) and returns FALSE.
    If lpPoint is valid, writes the 8-byte POINT structure and returns TRUE.
    """
    library = str(row.get("library", ""))
    if (library.casefold() != CURSOR_IMPORT_LIBRARY or
            row.get("name") != CURSOR_IMPORT_NAME):
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_has_permissions(
            engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 8)
        return False

    frame = bytes(engine.mem_read(esp, 8))
    return_address, lp_point = struct.unpack("<II", frame)
    import_index = int(row["index"])

    if lp_point == 0:
        teb = state.get("tls_current_teb", TEB_BASE)
        if not isinstance(teb, int) or teb == 0:
            _api_state_fault(state, 0, "current_teb_invalid")
            return False

        last_error_address = teb + LAST_ERROR_OFFSET
        if last_error_address > 0xFFFFFFFF or last_error_address + 4 > 0x100000000:
            _memory_fault(state, "write", last_error_address & 0xFFFFFFFF, 4)
            return False
        if not _range_has_permissions(
                engine, last_error_address, 4, unicorn_module.UC_PROT_WRITE,
                mapped_ranges):
            _memory_fault(state, "write", last_error_address, 4)
            return False

        engine.mem_write(last_error_address, struct.pack("<I", ERROR_NOACCESS))
        api = {
            "library": library,
            "name": CURSOR_IMPORT_NAME,
            "import_index": import_index,
            "tag": IMPORT_BASE + import_index,
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "arguments": [lp_point],
            "result": 0,
            "last_error_after": ERROR_NOACCESS,
            "outcome": "invalid_pointer",
            "profile": CURSOR_PROFILE,
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        }
        state.setdefault("api_calls", []).append(api)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if lp_point + 8 > 0x100000000:
        _memory_fault(state, "write", lp_point, 8)
        return False

    if not _range_has_permissions(
            engine, lp_point, 8, unicorn_module.UC_PROT_WRITE, mapped_ranges):
        _memory_fault(state, "write", lp_point, 8)
        return False

    coords = state.get("cursor_coords", (0, 0))
    engine.mem_write(lp_point, struct.pack("<ii", int(coords[0]), int(coords[1])))

    api = {
        "library": library,
        "name": CURSOR_IMPORT_NAME,
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 1,
        "return_address": return_address,
        "arguments": [lp_point],
        "result": 1,
        "outcome": "success",
        "profile": CURSOR_PROFILE,
        "esp_after": (esp + 8) & 0xFFFFFFFF,
    }
    state.setdefault("api_calls", []).append(api)
    engine.reg_write(registers.UC_X86_REG_EAX, 1)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
    state["resume"] = True
    return True


__all__ = [
    "CURSOR_IMPORT_LIBRARY",
    "CURSOR_IMPORT_NAME",
    "CURSOR_PROFILE",
    "_cursor_query_import",
]
