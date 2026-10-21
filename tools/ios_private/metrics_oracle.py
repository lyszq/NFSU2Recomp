#!/usr/bin/env python3
"""Bounded synthetic GetSystemMetrics contract for the private startup oracle."""
from __future__ import annotations

import struct
from typing import Any

METRICS_IMPORT_LIBRARY = "user32.dll"
METRICS_IMPORT_NAME = "GetSystemMetrics"
METRICS_PROFILE = "headless_default_metrics"
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34

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


def _metrics_query_import(engine: Any, registers: Any, unicorn_module: Any,
                          row: dict[str, Any],
                          mapped_ranges: list[tuple[int, int]],
                          state: dict[str, Any]) -> bool:
    """Model GetSystemMetrics(nIndex) in a headless guest process."""
    library = str(row.get("library", ""))
    if (library.casefold() != METRICS_IMPORT_LIBRARY or
            row.get("name") != METRICS_IMPORT_NAME):
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_has_permissions(
            engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 8)
        return False

    frame = bytes(engine.mem_read(esp, 8))
    return_address, n_index = struct.unpack("<II", frame)
    import_index = int(row["index"])

    if n_index == SM_SWAPBUTTON:
        result = 0  # FALSE: normal mouse buttons
        outcome = "success_sm_swapbutton"
    else:
        return False

    api = {
        "library": library,
        "name": METRICS_IMPORT_NAME,
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 1,
        "return_address": return_address,
        "arguments": [n_index],
        "result": result,
        "outcome": outcome,
        "profile": METRICS_PROFILE,
        "esp_after": (esp + 8) & 0xFFFFFFFF,
    }
    state.setdefault("api_calls", []).append(api)
    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
    state["resume"] = True
    return True


__all__ = [
    "METRICS_IMPORT_LIBRARY",
    "METRICS_IMPORT_NAME",
    "METRICS_PROFILE",
    "SM_SWAPBUTTON",
    "_metrics_query_import",
]
