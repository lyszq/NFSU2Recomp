#!/usr/bin/env python3
"""Bounded synthetic RegOpenKeyA contract for the private startup oracle.

This models only the five Win32 predefined root handles. It does not access the
host registry or claim that any subkey exists.
"""
from __future__ import annotations

import struct
from typing import Any


REGISTRY_IMPORT_LIBRARY = "advapi32.dll"
REGISTRY_IMPORT_NAME = "RegOpenKeyA"
REGISTRY_ROOTS = frozenset((
    0x80000000,  # HKEY_CLASSES_ROOT
    0x80000001,  # HKEY_CURRENT_USER
    0x80000002,  # HKEY_LOCAL_MACHINE
    0x80000003,  # HKEY_USERS
    0x80000005,  # HKEY_CURRENT_CONFIG
))
REGISTRY_PROFILE = "empty_predefined_roots"
MAX_SUBKEY_SCAN = 4096
ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_HANDLE = 6


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
    """Require the whole guest range to be mapped with the requested access."""
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


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _scan_subkey(engine: Any, unicorn_module: Any,
                 mapped_ranges: list[tuple[int, int]],
                 address: int) -> tuple[bool, bytes]:
    """Return (supported, bytes-through-NUL) without changing guest state."""
    if address == 0:
        return True, b""

    name = bytearray()
    for index in range(MAX_SUBKEY_SCAN):
        current = address + index
        if current > 0xFFFFFFFF:
            # Keep the guest stop target at the last representable byte, the
            # established convention for a 32-bit guest range overflow.
            raise _GuestMemoryFault("read", 0xFFFFFFFF, 1)
        if not _range_has_permissions(
                engine, current, 1, unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestMemoryFault("read", current, 1)
        byte = bytes(engine.mem_read(current, 1))
        if byte == b"\0":
            return True, bytes(name)
        name.extend(byte)
    # A non-terminated path within the bounded scan is outside this contract.
    return False, bytes(name)


class _GuestMemoryFault(Exception):
    def __init__(self, access: str, address: int, size: int):
        super().__init__(access, address, size)


def _registry_import(engine: Any, registers: Any, unicorn_module: Any,
                     row: dict[str, Any],
                     mapped_ranges: list[tuple[int, int]],
                     state: dict[str, Any]) -> bool:
    """Handle only ADVAPI32!RegOpenKeyA over the empty predefined roots.

    Pointer faults stop at the import without changing guest registers or
    memory. Unknown/overlong strings and other imports remain unsupported.
    """
    library = str(row.get("library", ""))
    name = row.get("name")
    if library.casefold() != REGISTRY_IMPORT_LIBRARY or name != REGISTRY_IMPORT_NAME:
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    try:
        # Snapshot the complete stdcall frame before interpreting any argument.
        if not _range_has_permissions(
                engine, esp, 16, unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestMemoryFault("read", esp, 16)
        frame = bytes(engine.mem_read(esp, 16))
        return_address = _read_u32(frame, 0)
        root = _read_u32(frame, 4)
        subkey_address = _read_u32(frame, 8)
        output_address = _read_u32(frame, 12)

        supported, subkey = _scan_subkey(
            engine, unicorn_module, mapped_ranges, subkey_address)
        if not supported:
            return False

        if not output_address or not _range_has_permissions(
                engine, output_address, 4, unicorn_module.UC_PROT_WRITE,
                mapped_ranges):
            raise _GuestMemoryFault("write", output_address, 4)

        if root not in REGISTRY_ROOTS:
            result = ERROR_INVALID_HANDLE
            output_handle = 0
            outcome = "invalid_handle"
        elif subkey:
            # This profile intentionally contains no named subkeys.
            result = ERROR_FILE_NOT_FOUND
            output_handle = 0
            outcome = "key_not_found"
        else:
            result = ERROR_SUCCESS
            output_handle = root
            outcome = "opened_root"

        # All reads and access checks are complete. The only guest-memory write
        # is the caller's output DWORD; this may safely alias its saved frame.
        engine.mem_write(output_address, struct.pack("<I", output_handle))

        import_index = int(row["index"])
        api = {
            "library": library,
            "name": REGISTRY_IMPORT_NAME,
            "import_index": import_index,
            "tag": 0xF0000000 + import_index,
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 3,
            "return_address": return_address,
            "arguments": {
                "hKey": root,
                "lpSubKey": subkey_address,
                "phkResult": output_address,
            },
            "subkey": subkey.decode("latin-1"),
            "result": result,
            "output_handle": output_handle,
            "outcome": outcome,
            "profile": REGISTRY_PROFILE,
            "esp_after": (esp + 16) & 0xFFFFFFFF,
        }
        state.setdefault("api_calls", []).append(api)
        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 16) & 0xFFFFFFFF)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestMemoryFault as exc:
        access, address, size = exc.args
        _memory_fault(state, access, address, size)
        return False


__all__ = [
    "REGISTRY_IMPORT_LIBRARY",
    "REGISTRY_IMPORT_NAME",
    "REGISTRY_PROFILE",
    "REGISTRY_ROOTS",
    "_registry_import",
]
