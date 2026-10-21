#!/usr/bin/env python3
"""Bounded synthetic Win32 Toolhelp32 snapshot contract for the private startup oracle."""
from __future__ import annotations

import struct
from typing import Any


TOOLHELP_IMPORT_LIBRARY = "kernel32.dll"
SNAPSHOT_IMPORT_NAME = "CreateToolhelp32Snapshot"
PROCESS_FIRST_IMPORT_NAME = "Process32First"
PROCESS_NEXT_IMPORT_NAME = "Process32Next"
CLOSE_HANDLE_IMPORT_NAME = "CloseHandle"

TOOLHELP_PROFILE = "deterministic_toolhelp_fixture_v1"

# Win32 Toolhelp snapshot constants
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_INHERIT = 0x80000000
ALLOWED_SNAPSHOT_FLAGS = frozenset((
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPPROCESS | TH32CS_INHERIT,
))

SNAPSHOT_HANDLE_BASE = 0x00D10000
SNAPSHOT_HANDLE_MIN = 0x00D10001
SNAPSHOT_HANDLE_MAX = 0x00D10008
MAX_SNAPSHOTS = 8
INVALID_HANDLE_VALUE = 0xFFFFFFFF

# Win32 PROCESSENTRY32 structure layout
# Size: 296 bytes (0x128)
PROCESSENTRY32_SIZE = 296
DEFAULT_PROCESS_ID = 100
DEFAULT_THREAD_COUNT = 1
DEFAULT_PRIORITY_CLASS = 8  # NORMAL_PRIORITY_CLASS
DEFAULT_EXE_NAME = "SPEED2.EXE"

# Win32 Error Codes
ERROR_SUCCESS = 0
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_FILES = 18
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122

# System memory offsets
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34


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


def _api_state_fault(state: dict[str, Any], api_name: str, address: int,
                     reason: str) -> None:
    target = int(address) & 0xFFFFFFFF
    state["status"] = "GUEST_STOP_API_STATE"
    state["target"] = target
    state["api_state_fault"] = {
        "api": api_name,
        "address": target,
        "reason": reason,
    }


def _validated_snapshot_table(state: dict[str, Any], api_name: str
                              ) -> dict[int, dict[str, int]] | None:
    """Validate the bounded one-process snapshot table before using it."""
    if "snapshots" not in state:
        return {}
    snapshots = state["snapshots"]
    valid = isinstance(snapshots, dict) and len(snapshots) <= MAX_SNAPSHOTS
    if valid:
        for handle, row in snapshots.items():
            if (type(handle) is not int or
                    handle < SNAPSHOT_HANDLE_MIN or
                    handle > SNAPSHOT_HANDLE_MAX or
                    type(row) is not dict or
                    set(row) != {"iter_index", "process_id"} or
                    type(row["process_id"]) is not int or
                    row["process_id"] != DEFAULT_PROCESS_ID or
                    type(row["iter_index"]) is not int or
                    row["iter_index"] not in (0, 1)):
                valid = False
                break
    if not valid:
        _api_state_fault(state, api_name, 0, "toolhelp_snapshot_table_invalid")
        return None
    return snapshots


def _check_memory_access(engine: Any, unicorn_module: Any,
                         address: int, size: int,
                         permissions: int, access_type: str,
                         mapped_ranges: list[tuple[int, int]],
                         state: dict[str, Any]) -> bool:
    if address < 0 or address > 0xFFFFFFFF:
        _memory_fault(state, access_type, 0xFFFFFFFF, size)
        return False
    if address + size > 0x100000000:
        _memory_fault(state, access_type, address, size)
        return False
    if not _range_has_permissions(
            engine, address, size, permissions, mapped_ranges):
        _memory_fault(state, access_type, address, size)
        return False
    return True


def _set_last_error(engine: Any, registers: Any, unicorn_module: Any,
                    mapped_ranges: list[tuple[int, int]],
                    state: dict[str, Any], api_name: str,
                    error_code: int) -> bool:
    teb = state.get("tls_current_teb")
    if teb is None:
        try:
            fs = int(engine.reg_read(registers.UC_X86_REG_FS_BASE))
            if fs != 0:
                teb = fs
        except Exception:
            pass
        if teb is None:
            teb = TEB_BASE

    if not isinstance(teb, int) or teb == 0:
        _api_state_fault(state, api_name, 0, "current_teb_invalid")
        return False

    last_error_address = teb + LAST_ERROR_OFFSET
    if last_error_address < 0 or last_error_address > 0xFFFFFFFF:
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

    engine.mem_write(last_error_address, struct.pack("<I", error_code))
    return True


def _record_api(state: dict[str, Any], row: dict[str, Any],
                name: str, arguments: list[int], result: int,
                last_error: int | None, outcome: str,
                esp_before: int, argc: int, return_address: int) -> dict[str, Any]:
    import_index = int(row.get("index", 0))
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    pop_size = (argc + 1) * 4
    api: dict[str, Any] = {
        "library": library,
        "name": name,
        "import_index": import_index,
        "tag": IMPORT_BASE + import_index,
        "call_ip": state.get("last_ip", 0),
        "esp_before": esp_before,
        "argument_count": argc,
        "return_address": return_address,
        "arguments": arguments,
        "result": result,
        "outcome": outcome,
        "profile": TOOLHELP_PROFILE,
        "esp_after": (esp_before + pop_size) & 0xFFFFFFFF,
    }
    if last_error is not None:
        api["last_error_after"] = last_error
    state.setdefault("api_calls", []).append(api)
    return api


def create_toolhelp32_snapshot(engine: Any, registers: Any, unicorn_module: Any,
                               row: dict[str, Any],
                               mapped_ranges: list[tuple[int, int]],
                               state: dict[str, Any]) -> bool:
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    if library and library.casefold() != TOOLHELP_IMPORT_LIBRARY:
        return False
    name = row.get("name")
    if name and name != SNAPSHOT_IMPORT_NAME:
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _check_memory_access(
            engine, unicorn_module, esp, 12,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    frame = bytes(engine.mem_read(esp, 12))
    return_address, dw_flags, th32_process_id = struct.unpack("<III", frame)

    if dw_flags not in ALLOWED_SNAPSHOT_FLAGS:
        # These may be valid Win32 snapshot requests, but this fixture models
        # only process snapshots. Leave them for the strict unsupported path.
        return False

    snapshots = _validated_snapshot_table(state, SNAPSHOT_IMPORT_NAME)
    if snapshots is None:
        return False
    if len(snapshots) >= MAX_SNAPSHOTS:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                SNAPSHOT_IMPORT_NAME, ERROR_INSUFFICIENT_BUFFER):
            return False
        _record_api(
            state, row, SNAPSHOT_IMPORT_NAME, [dw_flags, th32_process_id],
            INVALID_HANDLE_VALUE, ERROR_INSUFFICIENT_BUFFER,
            "snapshot_limit_reached", esp, 2, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, INVALID_HANDLE_VALUE)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    allocated_handle = None
    for slot in range(1, MAX_SNAPSHOTS + 1):
        candidate = SNAPSHOT_HANDLE_BASE + slot
        if candidate not in snapshots:
            allocated_handle = candidate
            break

    if allocated_handle is None:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                SNAPSHOT_IMPORT_NAME, ERROR_INSUFFICIENT_BUFFER):
            return False
        _record_api(
            state, row, SNAPSHOT_IMPORT_NAME, [dw_flags, th32_process_id],
            INVALID_HANDLE_VALUE, ERROR_INSUFFICIENT_BUFFER,
            "snapshot_limit_reached", esp, 2, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, INVALID_HANDLE_VALUE)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    snapshots[allocated_handle] = {
        "iter_index": 0,
        "process_id": DEFAULT_PROCESS_ID,
    }
    state["snapshots"] = snapshots

    _record_api(
        state, row, SNAPSHOT_IMPORT_NAME, [dw_flags, th32_process_id],
        allocated_handle, None, "success", esp, 2, return_address)
    engine.reg_write(registers.UC_X86_REG_EAX, allocated_handle)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
    state["resume"] = True
    return True


def process32_first(engine: Any, registers: Any, unicorn_module: Any,
                   row: dict[str, Any],
                   mapped_ranges: list[tuple[int, int]],
                   state: dict[str, Any]) -> bool:
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    if library and library.casefold() != TOOLHELP_IMPORT_LIBRARY:
        return False
    name = row.get("name")
    if name and name != PROCESS_FIRST_IMPORT_NAME:
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _check_memory_access(
            engine, unicorn_module, esp, 12,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    frame = bytes(engine.mem_read(esp, 12))
    return_address, h_snapshot, lppe = struct.unpack("<III", frame)

    snapshots = _validated_snapshot_table(state, PROCESS_FIRST_IMPORT_NAME)
    if snapshots is None:
        return False
    if h_snapshot not in snapshots:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                PROCESS_FIRST_IMPORT_NAME, ERROR_INVALID_HANDLE):
            return False
        _record_api(
            state, row, PROCESS_FIRST_IMPORT_NAME, [h_snapshot, lppe],
            0, ERROR_INVALID_HANDLE, "invalid_handle", esp, 2, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if not _check_memory_access(
            engine, unicorn_module, lppe, 4,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    dw_size = struct.unpack("<I", engine.mem_read(lppe, 4))[0]
    if dw_size < PROCESSENTRY32_SIZE:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                PROCESS_FIRST_IMPORT_NAME, ERROR_INSUFFICIENT_BUFFER):
            return False
        _record_api(
            state, row, PROCESS_FIRST_IMPORT_NAME, [h_snapshot, lppe],
            0, ERROR_INSUFFICIENT_BUFFER, "insufficient_buffer", esp, 2,
            return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if not _check_memory_access(
            engine, unicorn_module, lppe, PROCESSENTRY32_SIZE,
            unicorn_module.UC_PROT_WRITE, "write", mapped_ranges, state):
        return False

    process_id = snapshots[h_snapshot].get("process_id", DEFAULT_PROCESS_ID)
    exe_name_bytes = (DEFAULT_EXE_NAME.encode("ascii") + b"\0").ljust(260, b"\0")
    entry_bytes = struct.pack(
        "<IIIIIIIiI260s",
        PROCESSENTRY32_SIZE,
        0,
        process_id,
        0,
        0,
        DEFAULT_THREAD_COUNT,
        0,
        DEFAULT_PRIORITY_CLASS,
        0,
        exe_name_bytes
    )
    engine.mem_write(lppe, entry_bytes)
    snapshots[h_snapshot]["iter_index"] = 1

    _record_api(
        state, row, PROCESS_FIRST_IMPORT_NAME, [h_snapshot, lppe],
        1, None, "success", esp, 2, return_address)
    engine.reg_write(registers.UC_X86_REG_EAX, 1)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
    state["resume"] = True
    return True


def process32_next(engine: Any, registers: Any, unicorn_module: Any,
                  row: dict[str, Any],
                  mapped_ranges: list[tuple[int, int]],
                  state: dict[str, Any]) -> bool:
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    if library and library.casefold() != TOOLHELP_IMPORT_LIBRARY:
        return False
    name = row.get("name")
    if name and name != PROCESS_NEXT_IMPORT_NAME:
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _check_memory_access(
            engine, unicorn_module, esp, 12,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    frame = bytes(engine.mem_read(esp, 12))
    return_address, h_snapshot, lppe = struct.unpack("<III", frame)

    snapshots = _validated_snapshot_table(state, PROCESS_NEXT_IMPORT_NAME)
    if snapshots is None:
        return False
    if h_snapshot not in snapshots:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                PROCESS_NEXT_IMPORT_NAME, ERROR_INVALID_HANDLE):
            return False
        _record_api(
            state, row, PROCESS_NEXT_IMPORT_NAME, [h_snapshot, lppe],
            0, ERROR_INVALID_HANDLE, "invalid_handle", esp, 2, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if not _check_memory_access(
            engine, unicorn_module, lppe, 4,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    dw_size = struct.unpack("<I", engine.mem_read(lppe, 4))[0]
    if dw_size < PROCESSENTRY32_SIZE:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                PROCESS_NEXT_IMPORT_NAME, ERROR_INSUFFICIENT_BUFFER):
            return False
        _record_api(
            state, row, PROCESS_NEXT_IMPORT_NAME, [h_snapshot, lppe],
            0, ERROR_INSUFFICIENT_BUFFER, "insufficient_buffer", esp, 2,
            return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    iter_index = snapshots[h_snapshot].get("iter_index", 0)
    if iter_index >= 1:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                PROCESS_NEXT_IMPORT_NAME, ERROR_NO_MORE_FILES):
            return False
        _record_api(
            state, row, PROCESS_NEXT_IMPORT_NAME, [h_snapshot, lppe],
            0, ERROR_NO_MORE_FILES, "no_more_files", esp, 2, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
        state["resume"] = True
        return True

    if not _check_memory_access(
            engine, unicorn_module, lppe, PROCESSENTRY32_SIZE,
            unicorn_module.UC_PROT_WRITE, "write", mapped_ranges, state):
        return False

    process_id = snapshots[h_snapshot].get("process_id", DEFAULT_PROCESS_ID)
    exe_name_bytes = (DEFAULT_EXE_NAME.encode("ascii") + b"\0").ljust(260, b"\0")
    entry_bytes = struct.pack(
        "<IIIIIIIiI260s",
        PROCESSENTRY32_SIZE,
        0,
        process_id,
        0,
        0,
        DEFAULT_THREAD_COUNT,
        0,
        DEFAULT_PRIORITY_CLASS,
        0,
        exe_name_bytes
    )
    engine.mem_write(lppe, entry_bytes)
    snapshots[h_snapshot]["iter_index"] = 1

    _record_api(
        state, row, PROCESS_NEXT_IMPORT_NAME, [h_snapshot, lppe],
        1, None, "success", esp, 2, return_address)
    engine.reg_write(registers.UC_X86_REG_EAX, 1)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 12) & 0xFFFFFFFF)
    state["resume"] = True
    return True


def toolhelp_close_handle(engine: Any, registers: Any, unicorn_module: Any,
                         row: dict[str, Any],
                         mapped_ranges: list[tuple[int, int]],
                         state: dict[str, Any]) -> bool:
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    if library and library.casefold() != TOOLHELP_IMPORT_LIBRARY:
        return False
    name = row.get("name")
    if name and name != CLOSE_HANDLE_IMPORT_NAME:
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _check_memory_access(
            engine, unicorn_module, esp, 8,
            unicorn_module.UC_PROT_READ, "read", mapped_ranges, state):
        return False

    frame = bytes(engine.mem_read(esp, 8))
    return_address, h_object = struct.unpack("<II", frame)

    if h_object < SNAPSHOT_HANDLE_MIN or h_object > SNAPSHOT_HANDLE_MAX:
        return False

    snapshots = _validated_snapshot_table(state, CLOSE_HANDLE_IMPORT_NAME)
    if snapshots is None:
        return False
    if h_object in snapshots:
        del snapshots[h_object]
        _record_api(
            state, row, CLOSE_HANDLE_IMPORT_NAME, [h_object],
            1, None, "success", esp, 1, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 1)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    else:
        if not _set_last_error(
                engine, registers, unicorn_module, mapped_ranges, state,
                CLOSE_HANDLE_IMPORT_NAME, ERROR_INVALID_HANDLE):
            return False
        _record_api(
            state, row, CLOSE_HANDLE_IMPORT_NAME, [h_object],
            0, ERROR_INVALID_HANDLE, "invalid_handle", esp, 1, return_address)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True


def toolhelp_import(engine: Any, registers: Any, unicorn_module: Any,
                    row: dict[str, Any],
                    mapped_ranges: list[tuple[int, int]],
                    state: dict[str, Any]) -> bool:
    library = str(row.get("library", TOOLHELP_IMPORT_LIBRARY))
    if library and library.casefold() != TOOLHELP_IMPORT_LIBRARY:
        return False
    name = row.get("name")
    if name == SNAPSHOT_IMPORT_NAME:
        return create_toolhelp32_snapshot(
            engine, registers, unicorn_module, row, mapped_ranges, state)
    elif name == PROCESS_FIRST_IMPORT_NAME:
        return process32_first(
            engine, registers, unicorn_module, row, mapped_ranges, state)
    elif name == PROCESS_NEXT_IMPORT_NAME:
        return process32_next(
            engine, registers, unicorn_module, row, mapped_ranges, state)
    elif name == CLOSE_HANDLE_IMPORT_NAME:
        return toolhelp_close_handle(
            engine, registers, unicorn_module, row, mapped_ranges, state)
    return False


CreateToolhelp32Snapshot = create_toolhelp32_snapshot
Process32First = process32_first
Process32Next = process32_next
_toolhelp_import = toolhelp_import

__all__ = [
    "TOOLHELP_IMPORT_LIBRARY",
    "SNAPSHOT_IMPORT_NAME",
    "PROCESS_FIRST_IMPORT_NAME",
    "PROCESS_NEXT_IMPORT_NAME",
    "CLOSE_HANDLE_IMPORT_NAME",
    "TOOLHELP_PROFILE",
    "TH32CS_SNAPPROCESS",
    "TH32CS_INHERIT",
    "ALLOWED_SNAPSHOT_FLAGS",
    "SNAPSHOT_HANDLE_BASE",
    "SNAPSHOT_HANDLE_MIN",
    "SNAPSHOT_HANDLE_MAX",
    "MAX_SNAPSHOTS",
    "INVALID_HANDLE_VALUE",
    "PROCESSENTRY32_SIZE",
    "DEFAULT_PROCESS_ID",
    "DEFAULT_THREAD_COUNT",
    "DEFAULT_PRIORITY_CLASS",
    "DEFAULT_EXE_NAME",
    "ERROR_SUCCESS",
    "ERROR_INVALID_HANDLE",
    "ERROR_NO_MORE_FILES",
    "ERROR_INVALID_PARAMETER",
    "ERROR_INSUFFICIENT_BUFFER",
    "TEB_BASE",
    "LAST_ERROR_OFFSET",
    "IMPORT_BASE",
    "create_toolhelp32_snapshot",
    "process32_first",
    "process32_next",
    "toolhelp_close_handle",
    "toolhelp_import",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "_toolhelp_import",
]
