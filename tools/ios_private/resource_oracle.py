#!/usr/bin/env python3
"""Bounded synthetic USER32 resource and virtual shared-cursor contracts."""
from __future__ import annotations

import struct
from typing import Any

from window_oracle import _memory_fault, _range_has_permissions


RESOURCE_IMPORT_LIBRARY = "user32.dll"
RESOURCE_IMPORT_NAME = "LoadIconA"
CURSOR_IMPORT_NAME = "LoadCursorA"
MISSING_ICON_PROFILE = "missing_icon_numeric_32512"
SHARED_CURSOR_PROFILE = "system_shared_cursor_32512"
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
ERROR_RESOURCE_TYPE_NOT_FOUND = 1813
IDI_APPLICATION_RESOURCE_ID = 32512
OCR_NORMAL_RESOURCE_ID = 32512
USER_OBJECT_HANDLE_BASE = 0x00B10001
USER_OBJECT_CAPACITY = 8


def _find_or_prepare_shared_cursor(
        state: dict[str, Any]) -> tuple[int, dict[str, Any] | None] | None:
    """Validate the virtual registry, then find or prepare a shared cursor."""
    objects = state.get("user_objects")
    if type(objects) is not dict or len(objects) > USER_OBJECT_CAPACITY:
        return None

    normalized: list[tuple[int, tuple[str, str, int, int, bool]]] = []
    for raw_handle, raw_entry in objects.items():
        if (type(raw_handle) is not int or
                raw_handle < USER_OBJECT_HANDLE_BASE or
                raw_handle >= USER_OBJECT_HANDLE_BASE + USER_OBJECT_CAPACITY or
                type(raw_entry) is not dict or
                type(raw_entry.get("handle")) is not int or
                raw_entry["handle"] != raw_handle):
            return None

        kind = raw_entry.get("kind")
        origin = raw_entry.get("origin")
        system_id = raw_entry.get("system_id")
        module = raw_entry.get("module")
        shared_value = raw_entry.get("shared")
        if (type(kind) is not str or kind not in ("ICON", "CURSOR") or
                type(origin) is not str or
                origin not in ("PE_IMAGE", "SYSTEM_SHARED") or
                type(system_id) is not int or
                system_id < 0 or system_id > 0xFFFFFFFF or
                type(module) is not int or module < 0 or module > 0xFFFFFFFF):
            return None
        if type(shared_value) is bool:
            shared = shared_value
        elif type(shared_value) is int and shared_value in (0, 1):
            shared = bool(shared_value)
        else:
            return None

        if origin == "PE_IMAGE":
            if module == 0:
                return None
        elif module != 0 or not shared:
            return None
        normalized.append((raw_handle,
                           (kind, origin, system_id, module, shared)))

    matches = [
        handle for handle, identity in normalized
        if identity == ("CURSOR", "SYSTEM_SHARED",
                        OCR_NORMAL_RESOURCE_ID, 0, True)
    ]
    if len(matches) > 1:
        return None
    if matches:
        return matches[0], None

    used_handles = {handle for handle, _ in normalized}
    for slot in range(USER_OBJECT_CAPACITY):
        handle = USER_OBJECT_HANDLE_BASE + slot
        if handle not in used_handles:
            return handle, {
                "handle": handle,
                "kind": "CURSOR",
                "origin": "SYSTEM_SHARED",
                "system_id": OCR_NORMAL_RESOURCE_ID,
                "module": 0,
                "shared": True,
            }
    return None


def _api_state_fault(state: dict[str, Any], address: int,
                     reason: str) -> None:
    target = int(address) & 0xFFFFFFFF
    state["status"] = "GUEST_STOP_API_STATE"
    state["target"] = target
    state["api_state_fault"] = {
        "api": RESOURCE_IMPORT_NAME,
        "address": target,
        "reason": reason,
    }


def _resource_import(engine: Any, registers: Any, unicorn_module: Any,
                     row: dict[str, Any],
                     mapped_ranges: list[tuple[int, int]],
                     state: dict[str, Any]) -> bool:
    """Model one evidenced missing icon and one declared shared cursor.

    LoadIconA requires explicit parent-provided evidence that numeric resource
    32512 is absent from the current image. LoadCursorA(NULL, 32512) returns a
    typed virtual object from the per-guest table. Neither path reads resource
    bytes or captures a host handle.
    """
    library = str(row.get("library", ""))
    name = row.get("name")
    if (library.casefold() != RESOURCE_IMPORT_LIBRARY or
            name not in (RESOURCE_IMPORT_NAME, CURSOR_IMPORT_NAME)):
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_has_permissions(
            engine, esp, 12, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 12)
        return False

    # Snapshot all arguments before LastError can alias and overwrite the
    # return address or any part of this stdcall frame.
    frame = bytes(engine.mem_read(esp, 12))
    return_address, instance, icon_name = struct.unpack("<III", frame)

    import_index = int(row["index"])
    if name == CURSOR_IMPORT_NAME:
        if instance != 0 or icon_name != OCR_NORMAL_RESOURCE_ID:
            return False
        prepared = _find_or_prepare_shared_cursor(state)
        if prepared is None:
            return False
        handle, new_entry = prepared
        if new_entry is not None:
            state["user_objects"][handle] = new_entry

        state.setdefault("api_calls", []).append({
            "library": library,
            "name": CURSOR_IMPORT_NAME,
            "import_index": import_index,
            "tag": IMPORT_BASE + import_index,
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 2,
            "return_address": return_address,
            "arguments": [instance, icon_name],
            "result": handle,
            "outcome": "virtual_shared_object",
            "profile": SHARED_CURSOR_PROFILE,
            "esp_after": (esp + 12) & 0xFFFFFFFF,
        })
        engine.reg_write(registers.UC_X86_REG_EAX, handle)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    image_base = state.get("resource_image_base")
    if (state.get("resource_missing_application_icon") is not True or
            type(image_base) is not int or image_base <= 0 or
            image_base > 0xFFFFFFFF or instance != image_base or
            icon_name != IDI_APPLICATION_RESOURCE_ID):
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

    engine.mem_write(last_error_address,
                     struct.pack("<I", ERROR_RESOURCE_TYPE_NOT_FOUND))

    state.setdefault("api_calls", []).append({
        "library": library,
        "name": RESOURCE_IMPORT_NAME,
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 2,
        "return_address": return_address,
        "arguments": [instance, icon_name],
        "result": 0,
        "last_error_after": ERROR_RESOURCE_TYPE_NOT_FOUND,
        "outcome": "resource_not_found",
        "profile": MISSING_ICON_PROFILE,
        "esp_after": (esp + 12) & 0xFFFFFFFF,
    })
    engine.reg_write(registers.UC_X86_REG_EAX, 0)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
    state["resume"] = True
    return True


__all__ = [
    "ERROR_RESOURCE_TYPE_NOT_FOUND",
    "IDI_APPLICATION_RESOURCE_ID",
    "MISSING_ICON_PROFILE",
    "OCR_NORMAL_RESOURCE_ID",
    "RESOURCE_IMPORT_LIBRARY",
    "RESOURCE_IMPORT_NAME",
    "CURSOR_IMPORT_NAME",
    "SHARED_CURSOR_PROFILE",
    "USER_OBJECT_CAPACITY",
    "USER_OBJECT_HANDLE_BASE",
    "_resource_import",
]
