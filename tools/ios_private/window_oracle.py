#!/usr/bin/env python3
"""Bounded synthetic GetWindowRect contract for the private startup oracle."""
from __future__ import annotations

import struct
from typing import Any


WINDOW_IMPORT_LIBRARY = "user32.dll"
WINDOW_IMPORT_NAME = "GetWindowRect"
SUPPORTED_WINDOW_QUERIES = frozenset(("GetWindowRect", "GetClientRect", "GetSystemMetrics"))
WINDOW_PROFILE = "headless_no_guest_window"
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
ERROR_INVALID_WINDOW_HANDLE = 1400

SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_SWAPBUTTON = 23


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
    """Require one fully mapped guest range with the requested permission."""
    if not _range_is_mapped(address, size, mapped_ranges):
        return False
    end = address + size
    cursor = address
    for region_start, region_end, region_permissions in engine.mem_regions():
        # Unicorn reports an inclusive region end.
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
        "api": WINDOW_IMPORT_NAME,
        "address": target,
        "reason": reason,
    }


def _window_query_import(engine: Any, registers: Any, unicorn_module: Any,
                         row: dict[str, Any],
                         mapped_ranges: list[tuple[int, int]],
                         state: dict[str, Any]) -> bool:
    """Model only GetWindowRect(NULL, rect) in a headless guest process.

    Windows reports ERROR_INVALID_WINDOW_HANDLE before consulting the RECT
    pointer. The bounded oracle reproduces that behavior: it ignores the RECT
    argument, sets LastError, and returns FALSE. Other window handles remain
    unsupported; this function never creates or claims a guest window.
    """
    library = str(row.get("library", ""))
    if (library.casefold() != WINDOW_IMPORT_LIBRARY or
            row.get("name") not in SUPPORTED_WINDOW_QUERIES):
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF

    if row.get("name") == "GetSystemMetrics":
        if not _range_has_permissions(
                engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
            _memory_fault(state, "read", esp, 8)
            return False

        frame = bytes(engine.mem_read(esp, 8))
        return_address, metric = struct.unpack("<II", frame)
        import_index = int(row["index"])

        if metric == SM_SWAPBUTTON:
            result = 0
        elif metric == SM_CXSCREEN:
            result = 640
        elif metric == SM_CYSCREEN:
            result = 480
        else:
            result = 0

        api = {
            "library": library,
            "name": "GetSystemMetrics",
            "import_index": import_index,
            "tag": IMPORT_BASE + import_index,
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "arguments": [metric],
            "result": result,
            "outcome": "success",
            "profile": WINDOW_PROFILE,
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        }
        state.setdefault("api_calls", []).append(api)
        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if not _range_has_permissions(
            engine, esp, 12, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 12)
        return False

    # Capture all three DWORDs before a LastError write can alias the frame.
    frame = bytes(engine.mem_read(esp, 12))
    return_address, hwnd, rect_address = struct.unpack("<III", frame)
    if hwnd != 0:
        return False

    teb = state.get("tls_current_teb", TEB_BASE)
    if not isinstance(teb, int) or teb == 0:
        _api_state_fault(state, 0, "current_teb_invalid")
        return False

    last_error_address = teb + LAST_ERROR_OFFSET
    if last_error_address > 0xFFFFFFFF:
        _memory_fault(state, "write", 0xFFFFFFFF, 4)
        return False
    if last_error_address + 4 > 0x100000000:
        _memory_fault(state, "write", last_error_address, 4)
        return False
    if not _range_has_permissions(
            engine, last_error_address, 4, unicorn_module.UC_PROT_WRITE,
            mapped_ranges):
        _memory_fault(state, "write", last_error_address, 4)
        return False

    import_index = int(row["index"])
    engine.mem_write(last_error_address,
                     struct.pack("<I", ERROR_INVALID_WINDOW_HANDLE))

    api = {
        "library": library,
        "name": row["name"],
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 2,
        "return_address": return_address,
        "arguments": [hwnd, rect_address],
        "result": 0,
        "last_error_after": ERROR_INVALID_WINDOW_HANDLE,
        "outcome": "invalid_window_handle",
        "profile": WINDOW_PROFILE,
        "esp_after": (esp + 12) & 0xFFFFFFFF,
    }
    state.setdefault("api_calls", []).append(api)
    engine.reg_write(registers.UC_X86_REG_EAX, 0)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
    state["resume"] = True
    return True


__all__ = [
    "WINDOW_IMPORT_LIBRARY",
    "WINDOW_IMPORT_NAME",
    "SUPPORTED_WINDOW_QUERIES",
    "WINDOW_PROFILE",
    "SM_SWAPBUTTON",
    "SM_CXSCREEN",
    "SM_CYSCREEN",
    "_window_query_import",
]
