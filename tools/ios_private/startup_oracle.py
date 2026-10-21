#!/usr/bin/env python3
"""Build-host x86 reference for the authenticated, bounded startup prefix.

This module executes original PE instructions in Unicorn and services only the
explicitly declared guest Windows compatibility contracts. It stops before the
first unimplemented import. Its state is compared with statically lifted native
execution; the host-only reference engine is never bundled into iOS.
"""
from __future__ import annotations

from pathlib import Path
import struct
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DEPS = ROOT / "out" / "private-deps"
if PRIVATE_DEPS.is_dir():
    sys.path.insert(0, str(PRIVATE_DEPS))

SUPPORTED_EXE_SIZE = 4_788_224
SUPPORTED_EXE_SHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"
IMAGE_BASE = 0x00400000
ENTRY_POINT = 0x0075BCC7
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
PEB_BASE = 0x00C10000
TEB_SIZE = 0x20000
STACK_LO = 0x7F000000
STACK_HI = 0x7FF00000
STACK_SIZE = STACK_HI - STACK_LO
INITIAL_ESP = STACK_HI - 0x1000
ENTRY_RETURN = 0xDEADC0DE
EFLAGS_INITIAL = 0x202
EFLAGS_MASK = 0xCD5
FCW_INITIAL = 0x037F
FNV64_OFFSET = 14695981039346656037
FNV64_PRIME = 1099511628211
FNV64_MASK = 0xFFFFFFFFFFFFFFFF
INSTRUCTION_BUDGET = 250_000
STACK_WINDOW_BELOW = 0x1000
STACK_WINDOW_SIZE = 0x2000
LAST_ERROR_OFFSET = 0x34
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_HANDLE = 6
ERROR_NOT_ENOUGH_MEMORY = 8
HEAP_BASE = 0x20000000
HEAP_ARENA_SIZE = 0x04000000
HEAP_HEADER_SIZE = 0x4000
HEAP_GRANULE = 0x4000
HEAP_MAX_COUNT = 4
HEAP_MAX_BLOCKS = 256
HEAP_SUPPORTED_FLAGS = 0x01
HEAP_ALLOC_SUPPORTED_FLAGS = 0x09  # HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY
CRITICAL_SECTION_SIZE = 24
CRITICAL_SECTION_MAX_COUNT = 64
CRITICAL_SECTION_MAX_RECURSION = 0x7FFFFFFF
TEB_PROCESS_ID_OFFSET = 0x20
TEB_THREAD_ID_OFFSET = 0x24
SYSTEM_TIME_FILETIME_LOW = 0x927c8000
SYSTEM_TIME_FILETIME_HIGH = 0x01c4c66e
TICK_COUNT_DEFAULT = 1000
PERF_COUNTER_DEFAULT_LOW = 1000000
PERF_COUNTER_DEFAULT_HIGH = 0
TEB_TLS_SLOTS_OFFSET = 0xE10
TLS_SLOT_COUNT = 64
TLS_SLOT_BYTES = TLS_SLOT_COUNT * 4
TLS_MAX_THREAD_COUNT = 64
TLS_IMPORTS = {"TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue"}
PROCESS_BASE = 0x00C20000
PROCESS_RESERVED_SIZE = 0x10000
PROCESS_COMMITTED_SIZE = 0x4000
PROCESS_COMMAND_LINE = r"C:\NFSU2\SPEED2.EXE"
PROCESS_COMMAND_LINE_BYTES = PROCESS_COMMAND_LINE.encode("ascii") + b"\0"
PROCESS_ENV_A_BASE = PROCESS_BASE + 0x1000
PROCESS_ENV_W_BASE = PROCESS_BASE + 0x2000
PROCESS_ENV_LEASE_CAP = 32
PROCESS_PROFILE = "nfsu2_headless_xp"
PROCESS_CODE_PAGES = {"GetACP": 1252, "GetOEMCP": 437}
PROCESS_ENVIRONMENT_GETTERS = {"GetEnvironmentStrings", "GetEnvironmentStringsW"}
PROCESS_ENVIRONMENT_FREES = {"FreeEnvironmentStringsA", "FreeEnvironmentStringsW"}
PROCESS_IMPORTS = PROCESS_ENVIRONMENT_GETTERS | PROCESS_ENVIRONMENT_FREES
STARTUPINFOA_SIZE = 68
STD_INPUT_HANDLE = 0xFFFFFFF6
STD_OUTPUT_HANDLE = 0xFFFFFFF5
STD_ERROR_HANDLE = 0xFFFFFFF4
STD_HANDLE_SELECTORS = frozenset((STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                                  STD_ERROR_HANDLE))
BOUNDARY_ARGUMENT_COUNTS = {
    "RegOpenKeyA": 3,
    "IsProcessorFeaturePresent": 1,
    "GetWindowRect": 2,
    "GetCursorPos": 1,
    "GetStartupInfoA": 1,
    "GetStdHandle": 1,
    "GetFileType": 1,
    "SetHandleCount": 1,
    "GetCommandLineA": 0,
    "GetEnvironmentStrings": 0,
    "GetEnvironmentStringsW": 0,
    "FreeEnvironmentStringsA": 1,
    "FreeEnvironmentStringsW": 1,
    "GetACP": 0,
    "GetOEMCP": 0,
    "GetCurrentThreadId": 0,
    "TlsAlloc": 0,
    "TlsFree": 1,
    "TlsGetValue": 1,
    "TlsSetValue": 2,
    "HeapCreate": 3,
    "HeapAlloc": 3,
    "HeapReAlloc": 4,
    "HeapFree": 3,
    "HeapSize": 3,
    "HeapDestroy": 1,
    "InitializeCriticalSection": 1,
    "EnterCriticalSection": 1,
    "TryEnterCriticalSection": 1,
    "LeaveCriticalSection": 1,
    "DeleteCriticalSection": 1,
    "WideCharToMultiByte": 8,
    "GetCPInfo": 2,
    "GetModuleFileNameA": 3,
    "GetStringTypeW": 4,
    "GetStringTypeA": 5,
    "LCMapStringW": 6,
    "LCMapStringA": 6,
    "MultiByteToWideChar": 6,
    "SetUnhandledExceptionFilter": 1,
    "GetSystemTimeAsFileTime": 1,
    "GetCurrentProcessId": 0,
    "GetTickCount": 0,
    "QueryPerformanceCounter": 1,
}
CRITICAL_SECTION_IMPORTS = {
    "InitializeCriticalSection",
    "EnterCriticalSection",
    "TryEnterCriticalSection",
    "LeaveCriticalSection",
    "DeleteCriticalSection",
}
SUPPORTED_IMPORTS = {
    ("advapi32.dll", "RegOpenKeyA"),
    ("kernel32.dll", "IsProcessorFeaturePresent"),
    ("user32.dll", "GetWindowRect"),
    ("kernel32.dll", "GetVersionExA"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetStartupInfoA"),
    ("kernel32.dll", "GetStdHandle"),
    ("kernel32.dll", "GetFileType"),
    ("kernel32.dll", "SetHandleCount"),
    ("kernel32.dll", "GetCommandLineA"),
    *(('kernel32.dll', name) for name in PROCESS_IMPORTS),
    ("kernel32.dll", "GetACP"),
    ("kernel32.dll", "GetOEMCP"),
    ("kernel32.dll", "GetCurrentThreadId"),
    ("kernel32.dll", "HeapCreate"),
    ("kernel32.dll", "HeapAlloc"),
    ("kernel32.dll", "HeapReAlloc"),
    *(("kernel32.dll", name) for name in CRITICAL_SECTION_IMPORTS),
    *(("kernel32.dll", name) for name in TLS_IMPORTS),
    ("kernel32.dll", "WideCharToMultiByte"),
    ("kernel32.dll", "GetCPInfo"),
    ("kernel32.dll", "GetModuleFileNameA"),
    ("kernel32.dll", "GetStringTypeW"),
    ("kernel32.dll", "GetStringTypeA"),
    ("kernel32.dll", "LCMapStringW"),
    ("kernel32.dll", "LCMapStringA"),
    ("kernel32.dll", "MultiByteToWideChar"),
    ("kernel32.dll", "HeapFree"),
    ("kernel32.dll", "HeapSize"),
    ("kernel32.dll", "SetUnhandledExceptionFilter"),
    ("kernel32.dll", "GetSystemTimeAsFileTime"),
    ("kernel32.dll", "GetCurrentProcessId"),
    ("kernel32.dll", "GetTickCount"),
    ("kernel32.dll", "QueryPerformanceCounter"),
}
ERROR_MOD_NOT_FOUND = 126

# Canonical Windows-1252 CT_CTYPE1 table matching runtime/guest_locale.c
_CT_CTYPE1_CP1252 = [
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220,
    0x0220, 0x0268, 0x0228, 0x0228, 0x0228, 0x0228, 0x0220, 0x0220,
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220,
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220,
    0x0248, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284,
    0x0284, 0x0284, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0210, 0x0210, 0x0210, 0x0210, 0x0220,
    0x0200, 0x0220, 0x0210, 0x0302, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0200, 0x0210, 0x0301, 0x0210, 0x0301, 0x0220, 0x0301, 0x0220,
    0x0220, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0200, 0x0200, 0x0302, 0x0210, 0x0302, 0x0220, 0x0302, 0x0301,
    0x0248, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0312, 0x0210, 0x0210, 0x0230, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0214, 0x0214, 0x0210, 0x0312, 0x0210, 0x0210,
    0x0210, 0x0214, 0x0312, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0210,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0210,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302
]


def _fnv1a64(data: bytes | bytearray | memoryview) -> int:
    value = FNV64_OFFSET
    for byte in memoryview(data).cast("B"):
        value = ((value ^ byte) * FNV64_PRIME) & FNV64_MASK
    return value


def _initialize_process_arena(engine: Any, image_base: int,
                              image_size: int, unicorn_module: Any) -> dict[str, Any]:
    """Commit and populate the canonical guest process configuration region."""
    if (image_size <= 0 or image_base < 0 or image_base > 0xFFFFFFFF or
            image_size > 0x100000000 - image_base):
        raise ValueError("guest image range is empty or outside PE32 address space")
    image_end = image_base + image_size
    process_end = PROCESS_BASE + PROCESS_RESERVED_SIZE
    if image_base < process_end and PROCESS_BASE < image_end:
        raise ValueError("guest image overlaps the reserved process arena")

    for region_start, region_end, _permissions in engine.mem_regions():
        region_end += 1
        if region_start < process_end and PROCESS_BASE < region_end:
            raise ValueError("process arena overlaps an existing accessible VM region")

    committed = bytearray(PROCESS_COMMITTED_SIZE)
    committed[:len(PROCESS_COMMAND_LINE_BYTES)] = PROCESS_COMMAND_LINE_BYTES
    env_a_offset = PROCESS_ENV_A_BASE - PROCESS_BASE
    committed[env_a_offset:env_a_offset + 2] = b"\0\0"
    env_w_offset = PROCESS_ENV_W_BASE - PROCESS_BASE
    committed[env_w_offset:env_w_offset + 4] = b"\0\0\0\0"

    permissions = unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE
    engine.mem_map(PROCESS_BASE, PROCESS_COMMITTED_SIZE, permissions)
    engine.mem_write(PROCESS_BASE, bytes(committed))
    return {
        "initialized": 1,
        "base": PROCESS_BASE,
        "reserved_size": PROCESS_RESERVED_SIZE,
        "committed_size": PROCESS_COMMITTED_SIZE,
        "profile": PROCESS_PROFILE,
        "command_line": PROCESS_COMMAND_LINE,
        "command_line_address": PROCESS_BASE,
        "command_line_size": len(PROCESS_COMMAND_LINE_BYTES),
        "environment_a_address": PROCESS_ENV_A_BASE,
        "environment_a_size": 2,
        "environment_w_address": PROCESS_ENV_W_BASE,
        "environment_w_size": 4,
        "environment_a_refs": 0,
        "environment_w_refs": 0,
    }


def _read_u32(engine: Any, address: int) -> int:
    return struct.unpack("<I", engine.mem_read(address, 4))[0]


def _range_is_mapped(address: int, size: int, ranges: list[tuple[int, int]]) -> bool:
    if address < 0 or size <= 0 or address > 0xFFFFFFFF or size > 0x100000000 - address:
        return False
    end = address + size
    return any(start <= address and end <= stop for start, stop in ranges)


def _range_has_permissions(engine: Any, address: int, size: int, permissions: int,
                           ranges: list[tuple[int, int]]) -> bool:
    """Require a whole guest range to be mapped and have the requested Unicorn permissions."""
    if not _range_is_mapped(address, size, ranges):
        return False
    end = address + size
    cursor = address
    for region_start, region_end, region_permissions in engine.mem_regions():
        region_end += 1  # Unicorn reports inclusive region ends.
        if region_end <= cursor or region_start >= end:
            continue
        if region_start > cursor or region_permissions & permissions != permissions:
            return False
        cursor = min(end, region_end)
        if cursor == end:
            return True
    return False


class _GuestPointerFault(Exception):
    def __init__(self, access: str, address: int, size: int):
        super().__init__(access, address, size)


def _is_processor_feature_present(engine, registers, unicorn_module, row, mapped_ranges, state):
    if row.get("library", "").casefold() != "kernel32.dll" or row.get("name") != "IsProcessorFeaturePresent":
        return False
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_has_permissions(engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 8}
        return False
    ret, feature = struct.unpack("<2I", engine.mem_read(esp, 8))
    if feature not in (6, 7, 10):
        return False
    # Static guest CPUID EDX25 advertises SSE; EDX26 clear means no SSE2.
    result = 1 if feature == 6 else 0
    state["api_calls"].append({"library": row["library"], "name": row["name"],
        "import_index": row["index"], "tag": IMPORT_BASE + row["index"],
        "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 1,
        "return_address": ret, "arguments": [feature], "result": result,
        "profile": "upstream_static_x86_006d8", "esp_after": (esp + 8) & 0xFFFFFFFF})
    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_EIP, ret)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
    state["resume"] = True
    return True


def _get_version_ex_a(engine: Any, registers: Any, import_row: dict[str, Any],
                      mapped_ranges: list[tuple[int, int]], state: dict[str, Any]) -> bool:
    """Implement only the known XP GetVersionExA contract at its import tag.

    The bool result reports whether the API returned to guest code. Bad guest
    pointers stop strictly as a memory fault; no API return is fabricated.
    """
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
    }
    state["api_calls"].append(api)
    try:
        if not _range_is_mapped(esp, 8, mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        argument = _read_u32(engine, esp + 4)
        api["return_address"] = return_address
        api["argument"] = argument
        if not _range_is_mapped(argument, 4, mapped_ranges):
            raise _GuestPointerFault("read", argument, 4)
        cb = _read_u32(engine, argument)
        api["structure_size"] = cb
        last_error_address = TEB_BASE + LAST_ERROR_OFFSET
        last_error_before = _read_u32(engine, last_error_address)
        api["last_error_before"] = last_error_before

        if cb not in (148, 156):
            result = 0
            _write_u32(engine, last_error_address, ERROR_INSUFFICIENT_BUFFER)
            api["outcome"] = "insufficient_buffer"
            api["last_error_after"] = ERROR_INSUFFICIENT_BUFFER
            api["error"] = ERROR_INSUFFICIENT_BUFFER
            api["output_size"] = 0
        else:
            if not _range_is_mapped(argument, cb, mapped_ranges):
                raise _GuestPointerFault("write", argument, cb)
            output = bytearray(cb)
            struct.pack_into("<IIII", output, 0, cb, 5, 1, 2600)
            struct.pack_into("<I", output, 16, 2)  # VER_PLATFORM_WIN32_NT
            if cb == 156:
                struct.pack_into("<HHHBB", output, 148, 0, 0, 0x0100, 1, 0)
            engine.mem_write(argument, bytes(output))
            result = 1
            api["outcome"] = "success"
            api["last_error_after"] = last_error_before
            api["output_size"] = cb
            api["version"] = {
                "major": 5,
                "minor": 1,
                "build": 2600,
                "platform": 2,
                "service_pack": "",
                "suite_mask": 0x0100 if cb == 156 else None,
                "product_type": 1 if cb == 156 else None,
            }

        # GetVersionExA is stdcall: BOOL return, then callee pops its one DWORD.
        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api["result"] = result
        api["esp_after"] = (esp + 8) & 0xFFFFFFFF
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_module_handle_a(engine: Any, registers: Any, import_row: dict[str, Any],
                         mapped_ranges: list[tuple[int, int]], image_base: int,
                         state: dict[str, Any]) -> bool:
    """Return only the actual main-module handle; no other modules are loaded."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
    }
    state["api_calls"].append(api)
    try:
        if not _range_is_mapped(esp, 8, mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        argument = _read_u32(engine, esp + 4)
        api["return_address"] = return_address
        api["argument"] = argument
        last_error_address = TEB_BASE + LAST_ERROR_OFFSET
        last_error_before = _read_u32(engine, last_error_address)
        api["last_error_before"] = last_error_before

        if argument == 0:
            match = "main_module_null_name"
            result = image_base
        else:
            module = bytearray()
            terminated = False
            for offset in range(260):
                address = argument + offset
                if not _range_is_mapped(address, 1, mapped_ranges):
                    raise _GuestPointerFault("read", address, 1)
                value = engine.mem_read(address, 1)[0]
                if value == 0:
                    terminated = True
                    break
                module.append(value)
            if not terminated:
                match = "unterminated_name_over_260"
                result = 0
            else:
                decoded = module.decode("latin-1")
                if decoded.casefold() == "speed2.exe":
                    match = "main_module_name"
                    result = image_base
                else:
                    match = "no_loaded_module_match"
                    result = 0

        if result == 0:
            _write_u32(engine, last_error_address, ERROR_MOD_NOT_FOUND)
            api["last_error_after"] = ERROR_MOD_NOT_FOUND
            api["error"] = ERROR_MOD_NOT_FOUND
        else:
            api["last_error_after"] = last_error_before
        api["outcome"] = "success" if result else "module_not_found"
        api["module_match"] = match
        api["result"] = result

        # GetModuleHandleA is stdcall with one pointer argument.
        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api["esp_after"] = (esp + 8) & 0xFFFFFFFF
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_current_thread_id(engine: Any, registers: Any, unicorn_module: Any,
                           import_row: dict[str, Any],
                           mapped_ranges: list[tuple[int, int]],
                           state: dict[str, Any]) -> bool:
    """Read the active guest TEB thread ID and return it with the x86 ABI."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 0,
    }
    state["api_calls"].append(api)

    def stop_state(reason: str, address: int, **details: Any) -> bool:
        api["outcome"] = "invalid_state"
        api["state_error"] = reason
        api.update(details)
        state["status"] = "GUEST_STOP_API_STATE"
        state["target"] = address & 0xFFFFFFFF
        state["api_state_fault"] = {
            "api": import_row["name"],
            "address": address & 0xFFFFFFFF,
            "reason": reason,
            **details,
        }
        return False

    def read_fault(address: int, size: int) -> None:
        if not _range_has_permissions(engine, address, size,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", address & 0xFFFFFFFF, size)

    try:
        read_fault(esp, 4)
        return_address = _read_u32(engine, esp)
        teb = int(state.get("tls_current_teb", TEB_BASE))
        thread_id_address = teb + TEB_THREAD_ID_OFFSET
        if (teb < 0 or teb > 0xFFFFFFFF or thread_id_address > 0xFFFFFFFF):
            raise _GuestPointerFault(
                "read", min(max(thread_id_address, 0), 0xFFFFFFFF), 4)
        read_fault(thread_id_address, 4)
        thread_id = _read_u32(engine, thread_id_address)
        api.update(return_address=return_address, teb=teb,
                   thread_id_address=thread_id_address, thread_id=thread_id,
                   arguments=[])
        if thread_id == 0:
            return stop_state("current_thread_id_invalid", thread_id_address)

        engine.reg_write(registers.UC_X86_REG_EAX, thread_id)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 4)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", result=thread_id,
                   esp_after=(esp + 4) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_startup_info_a(engine: Any, registers: Any, unicorn_module: Any,
                        import_row: dict[str, Any],
                        mapped_ranges: list[tuple[int, int]],
                        state: dict[str, Any]) -> bool:
    """Return the configured zeroed GUI/headless guest STARTUPINFOA value.

    This process policy deliberately does not copy host startup state. The
    caller's buffer is validated in full before any guest memory or CPU state
    is changed, and the return address is captured before writing so the
    output may alias the x86 call frame.
    """
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 1,
        "policy": "zeroed_gui_headless_xp",
    }
    state["api_calls"].append(api)

    def read_fault(address: int, size: int) -> None:
        if not _range_has_permissions(engine, address, size,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", address & 0xFFFFFFFF, size)

    def write_fault(address: int, size: int) -> None:
        if (address == 0 or
                not _range_has_permissions(engine, address, size,
                                           unicorn_module.UC_PROT_WRITE,
                                           mapped_ranges)):
            raise _GuestPointerFault("write", address & 0xFFFFFFFF, size)

    try:
        read_fault(esp, 8)
        return_address = _read_u32(engine, esp)
        output = _read_u32(engine, esp + 4)
        api.update(return_address=return_address, argument=output,
                   arguments=[output], output_size=STARTUPINFOA_SIZE)

        # Windows defines cb as the structure size. The guest policy uses a
        # fixed zeroed startup record with cb set and dwFlags left at zero;
        # it does not inherit real host handles, coordinates, or flags.
        write_fault(output, STARTUPINFOA_SIZE)
        startup_info = bytearray(STARTUPINFOA_SIZE)
        struct.pack_into("<I", startup_info, 0, STARTUPINFOA_SIZE)
        engine.mem_write(output, bytes(startup_info))

        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", result=None, dw_flags=0,
                   last_error_policy="preserved",
                   esp_after=(esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": size}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_std_handle(engine: Any, registers: Any, unicorn_module: Any,
                    import_row: dict[str, Any],
                    mapped_ranges: list[tuple[int, int]],
                    state: dict[str, Any]) -> bool:
    """Return NULL for the three standard streams in the headless guest.

    This process has no console and no inherited or redirected standard
    handles. Unknown selectors remain unsupported and do not fabricate an
    API result or LastError value.
    """
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ,
                                      mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        selector = _read_u32(engine, esp + 4)
        if selector not in STD_HANDLE_SELECTORS:
            return False

        stream = {
            STD_INPUT_HANDLE: "stdin",
            STD_OUTPUT_HANDLE: "stdout",
            STD_ERROR_HANDLE: "stderr",
        }[selector]
        state["api_calls"].append({
            "library": import_row["library"],
            "name": import_row["name"],
            "import_index": import_row["index"],
            "tag": IMPORT_BASE + import_row["index"],
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "argument": selector,
            "arguments": [selector],
            "stream": stream,
            "policy": "no_console_no_inherited_handles",
            "outcome": "success",
            "result": 0,
            "last_error_policy": "preserved",
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        })
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {
            "access": access,
            "address": int(address),
            "size": size,
        }
        return False


def _get_file_type(engine: Any, registers: Any, unicorn_module: Any,
                   import_row: dict[str, Any],
                   mapped_ranges: list[tuple[int, int]],
                   state: dict[str, Any]) -> bool:
    """Model the observed invalid-handle result in the no-file guest process.

    The guest issues no file handles. Only NULL and INVALID_HANDLE_VALUE are
    modeled here; other nonzero handles remain unsupported instead of being
    assigned a fabricated file type.
    """
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF

    def stop_memory(access: str, address: int, size: int) -> bool:
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = address & 0xFFFFFFFF
        state["memory_fault"] = {
            "access": access,
            "address": int(address),
            "size": size,
        }
        return False

    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ,
                                      mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        handle = _read_u32(engine, esp + 4)
        if handle not in (0, 0xFFFFFFFF):
            return False

        teb = int(state.get("tls_current_teb", TEB_BASE))
        if teb == 0:
            state["status"] = "GUEST_STOP_API_STATE"
            state["target"] = 0
            state["api_state_fault"] = {
                "api": import_row["name"],
                "address": 0,
                "reason": "no_current_teb",
            }
            return False
        last_error_address = teb + LAST_ERROR_OFFSET
        if (teb < 0 or teb > 0xFFFFFFFF or last_error_address < 0 or
                last_error_address > 0xFFFFFFFF or
                last_error_address + 4 > 0x100000000 or
                not _range_has_permissions(engine, last_error_address, 4,
                                           unicorn_module.UC_PROT_WRITE,
                                           mapped_ranges)):
            fault_address = min(max(last_error_address, 0), 0xFFFFFFFF)
            raise _GuestPointerFault("write", fault_address, 4)

        api = {
            "library": import_row["library"],
            "name": import_row["name"],
            "import_index": import_row["index"],
            "tag": IMPORT_BASE + import_row["index"],
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "argument": handle,
            "arguments": [handle],
            "outcome": "invalid_handle",
            "result": 0,
            "last_error_after": ERROR_INVALID_HANDLE,
            "last_error_policy": "set_invalid_handle",
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        }
        _write_u32(engine, last_error_address, ERROR_INVALID_HANDLE)
        state["api_calls"].append(api)
        engine.reg_write(registers.UC_X86_REG_EAX, 0)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        return stop_memory(access, address, size)


def _set_handle_count(engine: Any, registers: Any, unicorn_module: Any,
                      import_row: dict[str, Any],
                      mapped_ranges: list[tuple[int, int]],
                      state: dict[str, Any]) -> bool:
    """Apply the Windows Win32 no-op contract and return the requested UINT."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ,
                                      mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        requested_count = _read_u32(engine, esp + 4)

        state["api_calls"].append({
            "library": import_row["library"],
            "name": import_row["name"],
            "import_index": import_row["index"],
            "tag": IMPORT_BASE + import_row["index"],
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "argument": requested_count,
            "arguments": [requested_count],
            "outcome": "success",
            "policy": "windows_win32_no_effect",
            "result": requested_count,
            "last_error_policy": "preserved",
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        })
        engine.reg_write(registers.UC_X86_REG_EAX, requested_count)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {
            "access": access,
            "address": int(address),
            "size": size,
        }
        return False


def _get_system_time_as_file_time(engine: Any, registers: Any, unicorn_module: Any,
                                  import_row: dict[str, Any],
                                  mapped_ranges: list[tuple[int, int]],
                                  state: dict[str, Any]) -> bool:
    """Write 64-bit UTC FILETIME to pointer argument and return."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 1,
    }
    state["api_calls"].append(api)

    def write_fault(address: int, size: int) -> None:
        if not _range_has_permissions(engine, address, size,
                                      unicorn_module.UC_PROT_WRITE, mapped_ranges):
            raise _GuestPointerFault("write", address & 0xFFFFFFFF, size)

    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        target_ptr = _read_u32(engine, esp + 4)
        api.update(return_address=return_address, target_ptr=target_ptr,
                   arguments=[target_ptr])
        if target_ptr == 0:
            raise _GuestPointerFault("write", 0, 8)
        write_fault(target_ptr, 8)
        _write_u32(engine, target_ptr, SYSTEM_TIME_FILETIME_LOW)
        _write_u32(engine, target_ptr + 4, SYSTEM_TIME_FILETIME_HIGH)

        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", esp_after=(esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_current_process_id(engine: Any, registers: Any, unicorn_module: Any,
                            import_row: dict[str, Any],
                            mapped_ranges: list[tuple[int, int]],
                            state: dict[str, Any]) -> bool:
    """Read active guest TEB process ID and return it with x86 ABI."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 0,
    }
    state["api_calls"].append(api)

    def read_fault(address: int, size: int) -> None:
        if not _range_has_permissions(engine, address, size,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", address & 0xFFFFFFFF, size)

    try:
        read_fault(esp, 4)
        return_address = _read_u32(engine, esp)
        teb = int(state.get("tls_current_teb", TEB_BASE))
        process_id_address = teb + TEB_PROCESS_ID_OFFSET
        if teb < 0 or teb > 0xFFFFFFFF or process_id_address > 0xFFFFFFFF:
            raise _GuestPointerFault("read", min(max(process_id_address, 0), 0xFFFFFFFF), 4)
        read_fault(process_id_address, 4)
        process_id = _read_u32(engine, process_id_address)
        api.update(return_address=return_address, teb=teb,
                   process_id_address=process_id_address, process_id=process_id,
                   arguments=[])
        if process_id == 0:
            api["outcome"] = "invalid_state"
            api["state_error"] = "current_process_id_invalid"
            state["status"] = "GUEST_STOP_API_STATE"
            state["target"] = process_id_address & 0xFFFFFFFF
            state["api_state_fault"] = {
                "api": import_row["name"],
                "address": process_id_address & 0xFFFFFFFF,
                "reason": "current_process_id_invalid",
            }
            return False

        engine.reg_write(registers.UC_X86_REG_EAX, process_id)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 4)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", result=process_id,
                   esp_after=(esp + 4) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _get_tick_count(engine: Any, registers: Any, unicorn_module: Any,
                    import_row: dict[str, Any],
                    mapped_ranges: list[tuple[int, int]],
                    state: dict[str, Any]) -> bool:
    """Return monotonic milliseconds count in EAX."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 0,
    }
    state["api_calls"].append(api)

    try:
        if not _range_has_permissions(engine, esp, 4,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", esp, 4)
        return_address = _read_u32(engine, esp)
        api.update(return_address=return_address, arguments=[])
        engine.reg_write(registers.UC_X86_REG_EAX, TICK_COUNT_DEFAULT)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 4)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", result=TICK_COUNT_DEFAULT,
                   esp_after=(esp + 4) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _query_performance_counter(engine: Any, registers: Any, unicorn_module: Any,
                               import_row: dict[str, Any],
                               mapped_ranges: list[tuple[int, int]],
                               state: dict[str, Any]) -> bool:
    """Write 64-bit performance counter value to pointer and return TRUE (1)."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 1,
    }
    state["api_calls"].append(api)

    def write_fault(address: int, size: int) -> None:
        if not _range_has_permissions(engine, address, size,
                                      unicorn_module.UC_PROT_WRITE, mapped_ranges):
            raise _GuestPointerFault("write", address & 0xFFFFFFFF, size)

    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ, mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        target_ptr = _read_u32(engine, esp + 4)
        api.update(return_address=return_address, target_ptr=target_ptr,
                   arguments=[target_ptr])
        if target_ptr == 0:
            raise _GuestPointerFault("write", 0, 8)
        write_fault(target_ptr, 8)
        _write_u32(engine, target_ptr, PERF_COUNTER_DEFAULT_LOW)
        _write_u32(engine, target_ptr + 4, PERF_COUNTER_DEFAULT_HIGH)

        engine.reg_write(registers.UC_X86_REG_EAX, 1)  # TRUE
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api.update(outcome="success", result=1,
                   esp_after=(esp + 8) & 0xFFFFFFFF)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _set_unhandled_exception_filter(engine: Any, registers: Any, unicorn_module: Any,
                                    import_row: dict[str, Any],
                                    mapped_ranges: list[tuple[int, int]],
                                    state: dict[str, Any]) -> bool:
    """Implement SetUnhandledExceptionFilter: track top-level filter and return previous."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    try:
        if not _range_has_permissions(engine, esp, 8,
                                      unicorn_module.UC_PROT_READ,
                                      mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        filter_address = _read_u32(engine, esp + 4)
        previous_filter = state.get("unhandled_exception_filter", 0)
        state["unhandled_exception_filter"] = filter_address

        state["api_calls"].append({
            "library": import_row["library"],
            "name": import_row["name"],
            "import_index": import_row["index"],
            "tag": IMPORT_BASE + import_row["index"],
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": 1,
            "return_address": return_address,
            "argument": filter_address,
            "arguments": [filter_address],
            "outcome": "success",
            "result": previous_filter,
            "previous_filter": previous_filter,
            "new_filter": filter_address,
            "last_error_policy": "preserved",
            "esp_after": (esp + 8) & 0xFFFFFFFF,
        })
        engine.reg_write(registers.UC_X86_REG_EAX, previous_filter)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {
            "access": access,
            "address": int(address),
            "size": size,
        }
        return False


def _guest_process_import(engine: Any, registers: Any, unicorn_module: Any,
                          import_row: dict[str, Any],
                          mapped_ranges: list[tuple[int, int]],
                          state: dict[str, Any]) -> bool:
    """Model the configured process strings, leases, and code-page imports."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    name = import_row["name"]
    if name in PROCESS_ENVIRONMENT_FREES:
        argument_count = 1
    elif name in PROCESS_ENVIRONMENT_GETTERS or name in PROCESS_CODE_PAGES or name == "GetCommandLineA":
        argument_count = 0
    else:
        return False
    frame_size = 4 * (argument_count + 1)

    def stop_memory(access: str, address: int, size: int) -> bool:
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = address & 0xFFFFFFFF
        state["memory_fault"] = {
            "access": access,
            "address": int(address),
            "size": size,
        }
        return False

    def stop_state(reason: str, **details: Any) -> bool:
        state["status"] = "GUEST_STOP_API_STATE"
        state["target"] = PROCESS_BASE
        state["api_state_fault"] = {
            "api": name,
            "address": PROCESS_BASE,
            "reason": reason,
            **details,
        }
        return False

    try:
        if not _range_has_permissions(engine, esp, frame_size,
                                      unicorn_module.UC_PROT_READ,
                                      mapped_ranges):
            raise _GuestPointerFault("read", esp, frame_size)
        frame = bytes(engine.mem_read(esp, frame_size))
        return_address = struct.unpack_from("<I", frame, 0)[0]
        argument = (struct.unpack_from("<I", frame, 4)[0]
                    if argument_count else None)

        process = state.get("process")
        if not isinstance(process, dict) or process.get("initialized") != 1:
            state["status"] = "GUEST_STOP_API_STATE"
            state["target"] = PROCESS_BASE
            state["api_state_fault"] = {
                "api": import_row["name"],
                "address": PROCESS_BASE,
                "reason": "process_not_initialized",
            }
            return False

        outcome = "success"
        last_error_policy = "preserved"
        last_error_before = None
        last_error_after = None
        reference_field = None
        string_address = None
        string_size = 0
        if name == "GetCommandLineA":
            result = int(process["command_line_address"])
            string_size = int(process["command_line_size"])
            if (result < 0 or result > 0xFFFFFFFF or string_size <= 0 or
                    string_size > 0x100000000 - result or
                    not _range_has_permissions(engine, result, string_size,
                                               unicorn_module.UC_PROT_READ,
                                               mapped_ranges)):
                fault_address = min(max(result, 0), 0xFFFFFFFF)
                raise _GuestPointerFault("read", fault_address, string_size)
            string_address = result
        elif name in PROCESS_ENVIRONMENT_GETTERS:
            is_wide = name == "GetEnvironmentStringsW"
            reference_field = "environment_w_refs" if is_wide else "environment_a_refs"
            string_address = int(process["environment_w_address"] if is_wide
                                  else process["environment_a_address"])
            string_size = 4 if is_wide else 2
            references = int(process[reference_field])
            if references < 0 or references > PROCESS_ENV_LEASE_CAP:
                return stop_state("environment_reference_count_invalid",
                                  encoding="wide" if is_wide else "narrow",
                                  references=references)
            if references >= PROCESS_ENV_LEASE_CAP:
                teb = int(state.get("tls_current_teb", TEB_BASE))
                if teb == 0:
                    return stop_state("no_current_teb")
                if teb < 0 or teb > 0xFFFFFFFF:
                    fault_address = min(max(teb, 0), 0xFFFFFFFF)
                    raise _GuestPointerFault("write", fault_address, 4)
                last_error_address = teb + LAST_ERROR_OFFSET
                if last_error_address > 0xFFFFFFFF:
                    raise _GuestPointerFault("write", 0xFFFFFFFF, 4)
                if not _range_has_permissions(
                        engine, last_error_address, 4,
                        unicorn_module.UC_PROT_WRITE, mapped_ranges):
                    raise _GuestPointerFault("write", last_error_address, 4)
                _write_u32(engine, last_error_address, ERROR_NOT_ENOUGH_MEMORY)
                last_error_after = ERROR_NOT_ENOUGH_MEMORY
                last_error_policy = "set_error_8"
                outcome = "lease_limit"
                result = 0
            else:
                if (string_address < 0 or string_address > 0xFFFFFFFF or
                        string_size > 0x100000000 - string_address or
                        not _range_has_permissions(
                            engine, string_address, string_size,
                            unicorn_module.UC_PROT_READ, mapped_ranges)):
                    fault_address = min(max(string_address, 0), 0xFFFFFFFF)
                    raise _GuestPointerFault("read", fault_address, string_size)
                process[reference_field] = references + 1
                result = string_address
        elif name in PROCESS_ENVIRONMENT_FREES:
            is_wide = name == "FreeEnvironmentStringsW"
            reference_field = "environment_w_refs" if is_wide else "environment_a_refs"
            expected_address = int(process["environment_w_address"] if is_wide
                                   else process["environment_a_address"])
            references = int(process[reference_field])
            if argument != expected_address or references <= 0:
                return stop_state(
                    "environment_free_mismatch",
                    encoding="wide" if is_wide else "narrow",
                    pointer=int(argument), expected_pointer=expected_address,
                    references=references)
            process[reference_field] = references - 1
            result = 1
        else:
            result = PROCESS_CODE_PAGES.get(name)
            if result is None:
                return False

        api = {
            "library": import_row["library"],
            "name": name,
            "import_index": import_row["index"],
            "tag": IMPORT_BASE + import_row["index"],
            "call_ip": state["last_ip"],
            "esp_before": esp,
            "argument_count": argument_count,
            "return_address": return_address,
            "argument": argument,
            "arguments": [] if argument_count == 0 else [argument],
            "outcome": outcome,
            "policy": PROCESS_PROFILE,
            "result": result,
            "last_error_policy": last_error_policy,
            "esp_after": (esp + frame_size) & 0xFFFFFFFF,
        }
        if last_error_before is not None:
            api["last_error_before"] = last_error_before
        if last_error_after is not None:
            api["last_error_after"] = last_error_after
        if string_address is not None:
            api["string_address"] = string_address
            api["string_size"] = string_size
        if reference_field is not None:
            api["references_after"] = int(process[reference_field])
        state["api_calls"].append(api)
        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_ESP,
                         (esp + frame_size) & 0xFFFFFFFF)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        return stop_memory(access, address, size)


def _round_up(value: int, granule: int) -> int:
    return (value + granule - 1) & ~(granule - 1)


def _heap_create(engine: Any, registers: Any, unicorn_module: Any,
                 import_row: dict[str, Any],
                 mapped_ranges: list[tuple[int, int]], state: dict[str, Any]) -> bool:
    """Mirror the native bounded HeapCreate bridge and committed heap pages."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_is_mapped(esp, 16, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 16}
        return False

    return_address = _read_u32(engine, esp)
    flags = _read_u32(engine, esp + 4)
    initial_size = _read_u32(engine, esp + 8)
    maximum_size = _read_u32(engine, esp + 12)
    if flags & ~HEAP_SUPPORTED_FLAGS:
        # The native import bridge leaves unsupported flags at the import stop.
        return False

    last_error_address = TEB_BASE + LAST_ERROR_OFFSET
    if not _range_is_mapped(last_error_address, 4, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = last_error_address
        state["memory_fault"] = {
            "access": "write", "address": last_error_address, "size": 4,
        }
        return False
    last_error_before = _read_u32(engine, last_error_address)
    rounded_maximum = _round_up(maximum_size, HEAP_GRANULE) if maximum_size else 0
    arena_capacity = HEAP_ARENA_SIZE - HEAP_HEADER_SIZE
    rc: str | None = None
    capacity = arena_capacity

    # guest_windows_import rounds HeapCreate's nonzero maximum before calling
    # guest_heap_create; keep its EINVAL/ENOMEM mapping and ordering exact.
    if rounded_maximum > 0xFFFFFFFF:
        rc = "ENOMEM"
    elif rounded_maximum and initial_size > rounded_maximum:
        rc = "EINVAL"
    elif rounded_maximum > arena_capacity:
        rc = "ENOMEM"
    else:
        if rounded_maximum:
            capacity = rounded_maximum
        if initial_size > capacity:
            rc = "ENOMEM"

    slot = next((index for index in range(HEAP_MAX_COUNT)
                 if index not in state["heaps"]), None)
    if rc is None and slot is None:
        rc = "ENOMEM"

    handle = 0
    committed_size = 0
    if rc is None:
        assert slot is not None
        handle = HEAP_BASE + slot * HEAP_ARENA_SIZE
        committed_size = _round_up(HEAP_HEADER_SIZE + initial_size, HEAP_GRANULE)
        try:
            engine.mem_map(handle, committed_size,
                           unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE)
            # Fresh native guest pages are zero-filled; model the committed
            # granule, including the tail beyond HEADER + initial_size.
            engine.mem_write(handle, bytes(committed_size))
        except Exception:
            state["status"] = "GUEST_STOP_MEMORY"
            state["target"] = handle
            state["memory_fault"] = {"access": "write", "address": handle,
                                      "size": committed_size}
            return False
        mapped_ranges.append((handle, handle + committed_size))
        heap = {
            "slot": slot,
            "handle": handle,
            "capacity": capacity,
            "initial_size": initial_size,
            "maximum_size": maximum_size,
            "rounded_maximum": rounded_maximum,
            "flags": flags,
            "committed_size": committed_size,
            "live_blocks": 0,
            "fixed": bool(maximum_size),
            "blocks": [],
        }
        state["heaps"][slot] = heap

    if rc is not None:
        error = ERROR_INVALID_PARAMETER if rc == "EINVAL" else ERROR_NOT_ENOUGH_MEMORY
        _write_u32(engine, last_error_address, error)
    else:
        error = last_error_before

    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "return_address": return_address,
        "flags": flags,
        "initial_size": initial_size,
        "maximum_size": maximum_size,
        "rounded_maximum": rounded_maximum,
        "result": handle,
        "last_error_before": last_error_before,
        "last_error_after": error,
        "outcome": "success" if rc is None else rc.lower(),
        "esp_after": (esp + 16) & 0xFFFFFFFF,
    }
    if rc is None:
        api["heap"] = {
            "slot": slot,
            "handle": handle,
            "capacity": capacity,
            "committed_size": committed_size,
            "live_blocks": 0,
            "fixed": bool(maximum_size),
            "blocks": [],
        }
    else:
        api["error"] = error
    state["api_calls"].append(api)

    engine.reg_write(registers.UC_X86_REG_EAX, handle)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 16)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    state["resume"] = True
    return True


def _heap_alloc(engine: Any, registers: Any, unicorn_module: Any,
                import_row: dict[str, Any],
                mapped_ranges: list[tuple[int, int]], state: dict[str, Any]) -> bool:
    """Apply the native bounded HeapAlloc first-fit and payload-zeroing policy."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_is_mapped(esp, 16, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 16}
        return False

    return_address = _read_u32(engine, esp)
    handle = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    size = _read_u32(engine, esp + 12)
    if flags & ~HEAP_ALLOC_SUPPORTED_FLAGS:
        # The Windows bridge leaves unsupported capabilities at the import
        # stop rather than silently dropping them.
        return False

    heaps = state.get("heaps", {})
    heap = next((record for record in heaps.values()
                 if record.get("handle") == handle), None)
    result = 0
    outcome = "invalid_heap"
    failure: str | None = "EINVAL"
    block_slot: int | None = None
    span = _round_up(size if size else 1, 8)
    candidate = 0
    if heap is not None:
        blocks = heap.get("blocks", [])
        if not isinstance(blocks, list):
            state["status"] = "GUEST_STOP_API_STATE"
            state["target"] = handle
            state["api_state_fault"] = {
                "api": "HeapAlloc",
                "address": handle,
                "reason": "heap_block_metadata_invalid",
            }
            return False
        fixed = bool(heap.get("fixed", heap.get("maximum_size", 0) != 0))
        capacity = int(heap["capacity"])
        if fixed and size >= 0x7FFF8:
            failure = "ENOMEM_FIXED_LIMIT"
        elif span > capacity:
            failure = "ENOMEM_CAPACITY"
        elif len(blocks) >= HEAP_MAX_BLOCKS:
            failure = "ENOMEM_BLOCK_LIMIT"
        else:
            block_slot = next((slot for slot in range(HEAP_MAX_BLOCKS)
                               if all(int(block.get("slot", i)) != slot
                                      for i, block in enumerate(blocks))), None)
            if block_slot is None:
                failure = "ENOMEM_BLOCK_LIMIT"
            else:
                candidate = handle + HEAP_HEADER_SIZE
                while True:
                    next_candidate = candidate
                    for block in blocks:
                        address = int(block["address"])
                        block_span = int(block["span"])
                        if (address and candidate + span > address and
                                candidate < address + block_span and
                                address + block_span > next_candidate):
                            next_candidate = address + block_span
                    if next_candidate == candidate:
                        break
                    candidate = next_candidate
                limit = handle + HEAP_HEADER_SIZE + capacity
                if candidate + span > limit:
                    failure = "ENOMEM_CAPACITY"
                else:
                    failure = None

    # HeapAlloc deliberately does not read or write LastError. All failures
    # return NULL and preserve the complete guest call state apart from ABI
    # return registers, just as the native import bridge does.
    committed_before = int(heap["committed_size"]) if heap is not None else 0
    committed_after = committed_before
    if failure is None:
        assert heap is not None and block_slot is not None
        commit_end = _round_up(candidate + span, HEAP_GRANULE)
        old_end = handle + committed_before
        if commit_end > old_end:
            tail_start = max(old_end, handle)
            tail_size = commit_end - tail_start
            try:
                engine.mem_map(
                    tail_start, tail_size,
                    unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE,
                )
                # New native anonymous guest pages are zero-filled on commit.
                engine.mem_write(tail_start, bytes(tail_size))
            except Exception:
                failure = "ENOMEM_COMMIT"
            else:
                for index, (start, end) in enumerate(mapped_ranges):
                    if start == handle and end == old_end:
                        mapped_ranges[index] = (handle, commit_end)
                        break
                else:
                    mapped_ranges.append((tail_start, commit_end))
                committed_after = commit_end - handle

    if failure is None:
        if flags & 0x08 and size:
            engine.mem_write(candidate, bytes(size))
        block = {"slot": block_slot, "address": candidate,
                 "size": size, "span": span}
        heap["blocks"].append(block)
        heap["live_blocks"] = len(heap["blocks"])
        heap["committed_size"] = committed_after
        result = candidate
        outcome = "allocated"
    else:
        outcome = "failed"

    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "return_address": return_address,
        "handle": handle,
        "flags": flags,
        "size": size,
        "span": span,
        "result": result,
        "last_error_policy": "preserved",
        "outcome": outcome,
        "failure": failure,
        "esp_after": (esp + 16) & 0xFFFFFFFF,
    }
    if heap is not None:
        api["heap"] = {
            "slot": heap["slot"],
            "handle": heap["handle"],
            "capacity": heap["capacity"],
            "committed_size": heap["committed_size"],
            "fixed": bool(heap.get("fixed", False)),
            "live_blocks": heap["live_blocks"],
            "blocks": [dict(block) for block in heap["blocks"]],
        }
    if result:
        api["allocation"] = {
            "slot": block_slot,
            "address": candidate,
            "size": size,
            "span": span,
            "zero_memory": bool(flags & 0x08),
        }
    state["api_calls"].append(api)

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 16)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    state["resume"] = True
    return True


def _commit_heap_pages(engine, unicorn_module, mapped_ranges, address, size):
    """Map only newly committed granules, preserving all existing payloads."""
    engine.mem_map(address, size, unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE)
    for index, (start, end) in enumerate(mapped_ranges):
        if end == address:
            mapped_ranges[index] = (start, address + size)
            break
    else:
        mapped_ranges.append((address, address + size))


def _heap_realloc(engine: Any, registers: Any, unicorn_module: Any,
                  import_row: dict[str, Any],
                  mapped_ranges: list[tuple[int, int]],
                  state: dict[str, Any]) -> bool:
    """Implement bounded HeapReAlloc matching runtime/guest_heap.c."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 4,
    }
    if not _range_is_mapped(esp, 20, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 20}
        return False

    return_address = _read_u32(engine, esp)
    handle = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_mem = _read_u32(engine, esp + 12)
    size = _read_u32(engine, esp + 16)
    api.update(return_address=return_address, handle=handle, flags=flags,
               address=lp_mem, size=size)

    if flags & ~(1 | 8 | 0x10):
        return False

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    heaps = state.get("heaps", {})
    heap = next((record for record in heaps.values()
                 if record.get("handle") == handle), None)
    result = 0
    span = _round_up(size if size else 1, 8)

    if heap is None or lp_mem == 0:
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        api["last_error_after"] = ERROR_INVALID_PARAMETER
    else:
        blocks = heap.get("blocks", [])
        block = next((b for b in blocks if int(b.get("address", 0)) == lp_mem), None)
        if block is None:
            _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
            api["last_error_after"] = ERROR_INVALID_PARAMETER
        else:
            old_size = int(block.get("size", 0))
            old_span = int(block.get("span", 0))
            fixed = bool(heap.get("fixed", heap.get("maximum_size", 0) != 0))
            capacity = int(heap["capacity"])
            if fixed and size >= 0x7FFF8:
                _write_u32(engine, last_error_addr, ERROR_NOT_ENOUGH_MEMORY)
                api["last_error_after"] = ERROR_NOT_ENOUGH_MEMORY
            elif span > capacity:
                _write_u32(engine, last_error_addr, ERROR_NOT_ENOUGH_MEMORY)
                api["last_error_after"] = ERROR_NOT_ENOUGH_MEMORY
            else:
                can_in_place = (lp_mem + span <= handle + HEAP_HEADER_SIZE + capacity)
                if can_in_place:
                    for ob in blocks:
                        ob_addr = int(ob.get("address", 0))
                        ob_span = int(ob.get("span", 0))
                        if ob_addr != lp_mem and ob_addr != 0:
                            if lp_mem + span > ob_addr and lp_mem < ob_addr + ob_span:
                                can_in_place = False
                                break
                if can_in_place:
                    if span > old_span:
                        commit_end = _round_up(lp_mem + span, HEAP_GRANULE)
                        old_end = handle + int(heap["committed_size"])
                        if commit_end > old_end:
                            _commit_heap_pages(engine, unicorn_module, mapped_ranges,
                                              old_end, commit_end - old_end)
                            heap["committed_size"] = commit_end - handle
                    if (flags & 8) and size > old_size:
                        engine.mem_write(lp_mem + old_size, b"\x00" * (size - old_size))
                    block["size"] = size
                    block["span"] = span
                    result = lp_mem
                    api["last_error_after"] = last_error_before
                else:
                    if flags & 0x10:
                        _write_u32(engine, last_error_addr, ERROR_NOT_ENOUGH_MEMORY)
                        api["last_error_after"] = ERROR_NOT_ENOUGH_MEMORY
                    else:
                        candidate = handle + HEAP_HEADER_SIZE
                        while True:
                            next_cand = candidate
                            for ob in blocks:
                                ob_addr = int(ob.get("address", 0))
                                ob_span = int(ob.get("span", 0))
                                if (ob_addr and candidate + span > ob_addr and
                                        candidate < ob_addr + ob_span and
                                        ob_addr + ob_span > next_cand):
                                    next_cand = ob_addr + ob_span
                            if next_cand == candidate:
                                break
                            candidate = next_cand
                        limit = handle + HEAP_HEADER_SIZE + capacity
                        if candidate + span > limit:
                            _write_u32(engine, last_error_addr, ERROR_NOT_ENOUGH_MEMORY)
                            api["last_error_after"] = ERROR_NOT_ENOUGH_MEMORY
                        else:
                            commit_end = _round_up(candidate + span, HEAP_GRANULE)
                            old_end = handle + int(heap["committed_size"])
                            if commit_end > old_end:
                                _commit_heap_pages(engine, unicorn_module, mapped_ranges,
                                                  old_end, commit_end - old_end)
                                heap["committed_size"] = commit_end - handle
                            if flags & 8:
                                engine.mem_write(candidate, b"\x00" * size)
                            copy_bytes = min(old_size, size)
                            if copy_bytes > 0:
                                old_data = engine.mem_read(lp_mem, copy_bytes)
                                engine.mem_write(candidate, bytes(old_data))
                            block["address"] = candidate
                            block["size"] = size
                            block["span"] = span
                            result = candidate
                            api["last_error_after"] = last_error_before

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 20) & 0xFFFFFFFF)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    api["result"] = result
    api["esp_after"] = (esp + 20) & 0xFFFFFFFF
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _heap_free(engine: Any, registers: Any, unicorn_module: Any,
               import_row: dict[str, Any],
               mapped_ranges: list[tuple[int, int]],
               state: dict[str, Any]) -> bool:
    """Implement HeapFree (required companion to complete __setargv cleanup)."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 3,
    }

    if not _range_is_mapped(esp, 16, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 16}
        return False

    ret_addr = _read_u32(engine, esp)
    handle = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_mem = _read_u32(engine, esp + 12)
    api.update(return_address=ret_addr, handle=handle, flags=flags, address=lp_mem)
    if flags & ~1:
        return False

    heaps = state.get("heaps", {})
    heap = next((h for h in heaps.values() if h.get("handle") == handle), None)
    found = heap is not None and (not lp_mem or any(b["address"] == lp_mem for b in heap["blocks"]))
    if found and lp_mem:
        blocks = heap.get("blocks", [])
        heap["blocks"] = [b for b in blocks if b.get("address") != lp_mem]
        heap["live_blocks"] = len(heap["blocks"])

    result = int(found)
    if not found:
        _write_u32(engine, TEB_BASE + LAST_ERROR_OFFSET, ERROR_INVALID_PARAMETER)
    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 16)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _heap_size(engine: Any, registers: Any, unicorn_module: Any,
               import_row: dict[str, Any],
               mapped_ranges: list[tuple[int, int]],
               state: dict[str, Any]) -> bool:
    """Implement HeapSize: return size of allocated block or -1."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_is_mapped(esp, 16, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 16}
        return False

    ret_addr = _read_u32(engine, esp)
    handle = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    address = _read_u32(engine, esp + 12)

    heaps = state.get("heaps", {})
    heap = next((h for h in heaps.values() if h.get("handle") == handle), None)
    block_size = None
    if heap is not None and address:
        blocks = heap.get("blocks", [])
        block = next((b for b in blocks if b.get("address") == address), None)
        if block:
            block_size = block.get("size")

    result = block_size if block_size is not None else 0xFFFFFFFF

    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 3,
        "return_address": ret_addr,
        "handle": handle,
        "flags": flags,
        "address": address,
        "result": result,
        "outcome": "found" if block_size is not None else "not_found",
        "last_error_policy": "preserved",
        "esp_after": (esp + 16) & 0xFFFFFFFF,
    }
    state["api_calls"].append(api)

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 16)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    state["resume"] = True
    return True


def _wide_char_to_multi_byte(engine: Any, registers: Any, unicorn_module: Any,
                             import_row: dict[str, Any],
                             mapped_ranges: list[tuple[int, int]],
                             state: dict[str, Any]) -> bool:
    """Implement WideCharToMultiByte for XP headless guest environment."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 8,
    }

    if not _range_is_mapped(esp, 36, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 36}
        return False

    ret_addr = _read_u32(engine, esp)
    code_page = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_wc = _read_u32(engine, esp + 12)
    cch_wc = struct.unpack("<i", engine.mem_read(esp + 16, 4))[0]
    lp_mb = _read_u32(engine, esp + 20)
    cb_mb = struct.unpack("<i", engine.mem_read(esp + 24, 4))[0]
    lp_default = _read_u32(engine, esp + 28)
    lp_used_default = _read_u32(engine, esp + 32)
    api.update(return_address=ret_addr, code_page=code_page, flags=flags,
               lp_wide_char_str=lp_wc, cch_wide_char=cch_wc,
               lp_multi_byte_str=lp_mb, cb_multi_byte=cb_mb)

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    if cch_wc == 0:
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cch_wc == -1:
            chars = []
            cur = lp_wc
            while True:
                if not _range_is_mapped(cur, 2, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 2}
                    return False
                wc = struct.unpack("<H", engine.mem_read(cur, 2))[0]
                chars.append(wc)
                cur += 2
                if wc == 0:
                    break
        else:
            if not _range_is_mapped(lp_wc, cch_wc * 2, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_wc
                state["memory_fault"] = {"access": "read", "address": lp_wc, "size": cch_wc * 2}
                return False
            raw = bytes(engine.mem_read(lp_wc, cch_wc * 2))
            chars = [struct.unpack_from("<H", raw, i * 2)[0] for i in range(cch_wc)]

        s = "".join(chr(c) for c in chars)
        enc = "cp1252" if code_page in (0, 1252) else ("cp437" if code_page == 1 else f"cp{code_page}")
        try:
            mb_bytes = _encode_cp1252(s, best_fit=not (flags & 0x400)) if enc == "cp1252" else s.encode(enc, errors="replace")
        except Exception:
            mb_bytes = s.encode("latin-1", errors="replace")

        req_len = len(mb_bytes)
        if cb_mb == 0:
            result = req_len
            api["outcome"] = "query_size"
        else:
            if cb_mb < req_len:
                _write_u32(engine, last_error_addr, ERROR_INSUFFICIENT_BUFFER)
                result = 0
                api["outcome"] = "insufficient_buffer"
            else:
                if not _range_is_mapped(lp_mb, req_len, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = lp_mb
                    state["memory_fault"] = {"access": "write", "address": lp_mb, "size": req_len}
                    return False
                engine.mem_write(lp_mb, mb_bytes)
                if lp_used_default != 0:
                    if not _range_is_mapped(lp_used_default, 4, mapped_ranges):
                        state["status"] = "GUEST_STOP_MEMORY"
                        state["target"] = lp_used_default
                        state["memory_fault"] = {"access": "write", "address": lp_used_default, "size": 4}
                        return False
                    _write_u32(engine, lp_used_default, 0)
                result = req_len
                api["outcome"] = "converted"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 36)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _get_cp_info(engine: Any, registers: Any, unicorn_module: Any,
                 import_row: dict[str, Any],
                 mapped_ranges: list[tuple[int, int]],
                 state: dict[str, Any]) -> bool:
    """Implement GetCPInfo returning SBCS Windows-1252 metrics."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 2,
    }

    if not _range_is_mapped(esp, 12, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 12}
        return False

    ret_addr = _read_u32(engine, esp)
    code_page = _read_u32(engine, esp + 4)
    lp_cp_info = _read_u32(engine, esp + 8)
    api.update(return_address=ret_addr, code_page=code_page, lp_cp_info=lp_cp_info)

    if not _range_is_mapped(lp_cp_info, 18, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = lp_cp_info
        state["memory_fault"] = {"access": "write", "address": lp_cp_info, "size": 18}
        return False

    # MaxCharSize=1, DefaultChar='?', LeadByte=[0]*12
    cpinfo_bytes = struct.pack("<IBB12sH", 1, 0x3F, 0x00, b"\x00" * 12, 0)
    engine.mem_write(lp_cp_info, cpinfo_bytes)

    result = 1
    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 12)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _get_module_file_name_a(engine: Any, registers: Any, unicorn_module: Any,
                            import_row: dict[str, Any],
                            mapped_ranges: list[tuple[int, int]],
                            image_base: int,
                            state: dict[str, Any]) -> bool:
    """Implement GetModuleFileNameA returning the configured executable path."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 3,
    }

    if not _range_is_mapped(esp, 16, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 16}
        return False

    ret_addr = _read_u32(engine, esp)
    h_module = _read_u32(engine, esp + 4)
    lp_filename = _read_u32(engine, esp + 8)
    n_size = _read_u32(engine, esp + 12)
    api.update(return_address=ret_addr, h_module=h_module,
               lp_filename=lp_filename, n_size=n_size)

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    if h_module not in (0, image_base):
        _write_u32(engine, last_error_addr, ERROR_MOD_NOT_FOUND)
        result = 0
        api["outcome"] = "module_not_found"
    elif n_size == 0:
        result = 0
        api["outcome"] = "zero_buffer"
    else:
        path_bytes = PROCESS_COMMAND_LINE.encode("ascii") + b"\0"
        if len(path_bytes) <= n_size:
            if not _range_is_mapped(lp_filename, len(path_bytes), mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_filename
                state["memory_fault"] = {"access": "write", "address": lp_filename, "size": len(path_bytes)}
                return False
            engine.mem_write(lp_filename, path_bytes)
            result = len(path_bytes) - 1
            api["outcome"] = "success"
        else:
            if not _range_is_mapped(lp_filename, n_size, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_filename
                state["memory_fault"] = {"access": "write", "address": lp_filename, "size": n_size}
                return False
            engine.mem_write(lp_filename, path_bytes[:n_size])
            _write_u32(engine, last_error_addr, ERROR_INSUFFICIENT_BUFFER)
            result = n_size
            api["outcome"] = "insufficient_buffer"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 16)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


_CP1252_UNDEFINED = frozenset((0x81, 0x8D, 0x8F, 0x90, 0x9D))


def _decode_cp1252(raw):
    # Windows preserves the five undefined byte positions as C1 controls.
    return "".join(chr(b) if b in _CP1252_UNDEFINED else bytes((b,)).decode("cp1252") for b in raw)


def _encode_cp1252(text, *, best_fit=True):
    output = bytearray()
    for character in text:
        value = ord(character)
        if value in _CP1252_UNDEFINED:
            output.append(value)
        elif value == 0x0191 and best_fit:
            # Windows' CP1252 best-fit for the capital F with hook is 0x83.
            output.append(0x83)
        else:
            output.extend(character.encode("cp1252", errors="replace"))
    return bytes(output)


def _simple_windows_case(text, flags):
    # LCMapStringW(0409) preserves sharp-s and micro-sign. Python's full
    # Unicode casing expands/changes them, which is a different contract.
    if flags & 0x100:
        converted = (character.lower() for character in text)
    elif flags & 0x200:
        converted = (character if character in "\u00df\u00b5" else character.upper() for character in text)
    else:
        return text
    return "".join(mapped if len(mapped) == 1 else original
                   for original, mapped in zip(text, converted))


def _classify_windows_wide(value):
    if 0x80 <= value <= 0x9F:
        return 0x220
    if value < 256:
        return _CT_CTYPE1_CP1252[value]
    for byte in range(0x80, 0xA0):
        if ord(_decode_cp1252(bytes((byte,)))) == value:
            return _CT_CTYPE1_CP1252[byte]
    return 0x200  # Bounded profile, not a complete Unicode NLS database.


def _get_string_type_w(engine: Any, registers: Any, unicorn_module: Any,
                       import_row: dict[str, Any],
                       mapped_ranges: list[tuple[int, int]],
                       state: dict[str, Any]) -> bool:
    """Implement GetStringTypeW for Unicode character classification."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 4,
    }

    if not _range_is_mapped(esp, 20, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 20}
        return False

    ret_addr = _read_u32(engine, esp)
    info_type = _read_u32(engine, esp + 4)
    lp_src = _read_u32(engine, esp + 8)
    cch_src = struct.unpack("<i", engine.mem_read(esp + 12, 4))[0]
    lp_chartype = _read_u32(engine, esp + 16)
    api.update(return_address=ret_addr, info_type=info_type,
               lp_src=lp_src, cch_src=cch_src, lp_chartype=lp_chartype)

    if cch_src == 0 or info_type != 1:
        last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cch_src == -1:
            chars = []
            cur = lp_src
            while True:
                if not _range_is_mapped(cur, 2, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 2}
                    return False
                wc = struct.unpack("<H", engine.mem_read(cur, 2))[0]
                chars.append(wc)
                cur += 2
                if wc == 0:
                    break
        else:
            if not _range_is_mapped(lp_src, cch_src * 2, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_src
                state["memory_fault"] = {"access": "read", "address": lp_src, "size": cch_src * 2}
                return False
            raw = bytes(engine.mem_read(lp_src, cch_src * 2))
            chars = [struct.unpack_from("<H", raw, i * 2)[0] for i in range(cch_src)]

        if not _range_is_mapped(lp_chartype, len(chars) * 2, mapped_ranges):
            state["status"] = "GUEST_STOP_MEMORY"
            state["target"] = lp_chartype
            state["memory_fault"] = {"access": "write", "address": lp_chartype, "size": len(chars) * 2}
            return False

        types = [_classify_windows_wide(ch) for ch in chars]
        out_bytes = struct.pack(f"<{len(types)}H", *types)
        engine.mem_write(lp_chartype, out_bytes)
        result = 1
        api["outcome"] = "success"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 20)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _get_string_type_a(engine: Any, registers: Any, unicorn_module: Any,
                       import_row: dict[str, Any],
                       mapped_ranges: list[tuple[int, int]],
                       state: dict[str, Any]) -> bool:
    """Implement GetStringTypeA for ANSI character classification."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 5,
    }

    if not _range_is_mapped(esp, 24, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 24}
        return False

    ret_addr = _read_u32(engine, esp)
    locale = _read_u32(engine, esp + 4)
    info_type = _read_u32(engine, esp + 8)
    lp_src = _read_u32(engine, esp + 12)
    cch_src = struct.unpack("<i", engine.mem_read(esp + 16, 4))[0]
    lp_chartype = _read_u32(engine, esp + 20)
    api.update(return_address=ret_addr, locale=locale, info_type=info_type,
               lp_src=lp_src, cch_src=cch_src, lp_chartype=lp_chartype)

    if cch_src == 0 or info_type != 1:
        last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cch_src == -1:
            raw_bytes = bytearray()
            cur = lp_src
            while True:
                if not _range_is_mapped(cur, 1, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 1}
                    return False
                b = engine.mem_read(cur, 1)[0]
                raw_bytes.append(b)
                cur += 1
                if b == 0:
                    break
        else:
            if not _range_is_mapped(lp_src, cch_src, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_src
                state["memory_fault"] = {"access": "read", "address": lp_src, "size": cch_src}
                return False
            raw_bytes = bytes(engine.mem_read(lp_src, cch_src))

        if not _range_is_mapped(lp_chartype, len(raw_bytes) * 2, mapped_ranges):
            state["status"] = "GUEST_STOP_MEMORY"
            state["target"] = lp_chartype
            state["memory_fault"] = {"access": "write", "address": lp_chartype, "size": len(raw_bytes) * 2}
            return False

        types = [_CT_CTYPE1_CP1252[b] for b in raw_bytes]
        out_bytes = struct.pack(f"<{len(types)}H", *types)
        engine.mem_write(lp_chartype, out_bytes)
        result = 1
        api["outcome"] = "success"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 24)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _lc_map_string_w(engine: Any, registers: Any, unicorn_module: Any,
                     import_row: dict[str, Any],
                     mapped_ranges: list[tuple[int, int]],
                     state: dict[str, Any]) -> bool:
    """Implement LCMapStringW for case conversions and length querying."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 6,
    }

    if not _range_is_mapped(esp, 28, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 28}
        return False

    ret_addr = _read_u32(engine, esp)
    locale = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_src = _read_u32(engine, esp + 12)
    cch_src = struct.unpack("<i", engine.mem_read(esp + 16, 4))[0]
    lp_dest = _read_u32(engine, esp + 20)
    cch_dest = struct.unpack("<i", engine.mem_read(esp + 24, 4))[0]
    api.update(return_address=ret_addr, locale=locale, flags=flags,
               lp_src=lp_src, cch_src=cch_src, lp_dest=lp_dest, cch_dest=cch_dest)

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    if cch_src == 0:
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cch_src == -1:
            chars = []
            cur = lp_src
            while True:
                if not _range_is_mapped(cur, 2, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 2}
                    return False
                wc = struct.unpack("<H", engine.mem_read(cur, 2))[0]
                chars.append(wc)
                cur += 2
                if wc == 0:
                    break
        else:
            if not _range_is_mapped(lp_src, cch_src * 2, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_src
                state["memory_fault"] = {"access": "read", "address": lp_src, "size": cch_src * 2}
                return False
            raw = bytes(engine.mem_read(lp_src, cch_src * 2))
            chars = [struct.unpack_from("<H", raw, i * 2)[0] for i in range(cch_src)]

        s = "".join(chr(c) for c in chars)
        s = _simple_windows_case(s, flags)

        req_len = len(s)
        if cch_dest == 0:
            result = req_len
            api["outcome"] = "query_size"
        else:
            if cch_dest < req_len:
                _write_u32(engine, last_error_addr, ERROR_INSUFFICIENT_BUFFER)
                result = 0
                api["outcome"] = "insufficient_buffer"
            else:
                if not _range_is_mapped(lp_dest, req_len * 2, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = lp_dest
                    state["memory_fault"] = {"access": "write", "address": lp_dest, "size": req_len * 2}
                    return False
                engine.mem_write(lp_dest, s.encode("utf-16le"))
                result = req_len
                api["outcome"] = "mapped"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 28)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _lc_map_string_a(engine: Any, registers: Any, unicorn_module: Any,
                     import_row: dict[str, Any],
                     mapped_ranges: list[tuple[int, int]],
                     state: dict[str, Any]) -> bool:
    """Implement LCMapStringA for ANSI case conversions and length querying."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 6,
    }

    if not _range_is_mapped(esp, 28, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 28}
        return False

    ret_addr = _read_u32(engine, esp)
    locale = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_src = _read_u32(engine, esp + 12)
    cch_src = struct.unpack("<i", engine.mem_read(esp + 16, 4))[0]
    lp_dest = _read_u32(engine, esp + 20)
    cch_dest = struct.unpack("<i", engine.mem_read(esp + 24, 4))[0]
    api.update(return_address=ret_addr, locale=locale, flags=flags,
               lp_src=lp_src, cch_src=cch_src, lp_dest=lp_dest, cch_dest=cch_dest)

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    if cch_src == 0:
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cch_src == -1:
            raw = bytearray()
            cur = lp_src
            while True:
                if not _range_is_mapped(cur, 1, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 1}
                    return False
                b = engine.mem_read(cur, 1)[0]
                raw.append(b)
                cur += 1
                if b == 0:
                    break
        else:
            if not _range_is_mapped(lp_src, cch_src, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_src
                state["memory_fault"] = {"access": "read", "address": lp_src, "size": cch_src}
                return False
            raw = bytes(engine.mem_read(lp_src, cch_src))

        try:
            s = _decode_cp1252(raw)
        except Exception:
            s = raw.decode("latin-1", errors="replace")

        s = _simple_windows_case(s, flags)

        out_raw = _encode_cp1252(s)
        req_len = len(out_raw)
        if cch_dest == 0:
            result = req_len
            api["outcome"] = "query_size"
        else:
            if cch_dest < req_len:
                _write_u32(engine, last_error_addr, ERROR_INSUFFICIENT_BUFFER)
                result = 0
                api["outcome"] = "insufficient_buffer"
            else:
                if not _range_is_mapped(lp_dest, req_len, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = lp_dest
                    state["memory_fault"] = {"access": "write", "address": lp_dest, "size": req_len}
                    return False
                engine.mem_write(lp_dest, out_raw)
                result = req_len
                api["outcome"] = "mapped"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 28)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True


def _multi_byte_to_wide_char(engine: Any, registers: Any, unicorn_module: Any,
                             import_row: dict[str, Any],
                             mapped_ranges: list[tuple[int, int]],
                             state: dict[str, Any]) -> bool:
    """Implement MultiByteToWideChar (required companion for GetStringTypeW & LCMapStringW)."""
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": import_row["name"],
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": 6,
    }

    if not _range_is_mapped(esp, 28, mapped_ranges):
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = esp
        state["memory_fault"] = {"access": "read", "address": esp, "size": 28}
        return False

    ret_addr = _read_u32(engine, esp)
    code_page = _read_u32(engine, esp + 4)
    flags = _read_u32(engine, esp + 8)
    lp_mb = _read_u32(engine, esp + 12)
    cb_mb = struct.unpack("<i", engine.mem_read(esp + 16, 4))[0]
    lp_wc = _read_u32(engine, esp + 20)
    cch_wc = struct.unpack("<i", engine.mem_read(esp + 24, 4))[0]
    api.update(return_address=ret_addr, code_page=code_page, flags=flags,
               lp_multi_byte_str=lp_mb, cb_multi_byte=cb_mb,
               lp_wide_char_str=lp_wc, cch_wide_char=cch_wc)

    last_error_addr = TEB_BASE + LAST_ERROR_OFFSET
    last_error_before = _read_u32(engine, last_error_addr)
    api["last_error_before"] = last_error_before

    if cb_mb == 0:
        _write_u32(engine, last_error_addr, ERROR_INVALID_PARAMETER)
        result = 0
        api["outcome"] = "invalid_parameter"
    else:
        if cb_mb == -1:
            raw = bytearray()
            cur = lp_mb
            while True:
                if not _range_is_mapped(cur, 1, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = cur
                    state["memory_fault"] = {"access": "read", "address": cur, "size": 1}
                    return False
                b = engine.mem_read(cur, 1)[0]
                raw.append(b)
                cur += 1
                if b == 0:
                    break
        else:
            if not _range_is_mapped(lp_mb, cb_mb, mapped_ranges):
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = lp_mb
                state["memory_fault"] = {"access": "read", "address": lp_mb, "size": cb_mb}
                return False
            raw = bytes(engine.mem_read(lp_mb, cb_mb))

        enc = "cp1252" if code_page in (0, 1252) else ("cp437" if code_page == 1 else f"cp{code_page}")
        try:
            s = _decode_cp1252(raw) if enc == "cp1252" else raw.decode(enc, errors="replace")
        except Exception:
            s = raw.decode("latin-1", errors="replace")

        req_len = len(s)
        if cch_wc == 0:
            result = req_len
            api["outcome"] = "query_size"
        else:
            if cch_wc < req_len:
                _write_u32(engine, last_error_addr, ERROR_INSUFFICIENT_BUFFER)
                result = 0
                api["outcome"] = "insufficient_buffer"
            else:
                if not _range_is_mapped(lp_wc, req_len * 2, mapped_ranges):
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = lp_wc
                    state["memory_fault"] = {"access": "write", "address": lp_wc, "size": req_len * 2}
                    return False
                engine.mem_write(lp_wc, s.encode("utf-16le"))
                result = req_len
                api["outcome"] = "converted"

    engine.reg_write(registers.UC_X86_REG_EAX, result)
    engine.reg_write(registers.UC_X86_REG_ESP, esp + 28)
    engine.reg_write(registers.UC_X86_REG_EIP, ret_addr)
    api["result"] = result
    state["api_calls"].append(api)
    state["resume"] = True
    return True



def _critical_section_import(engine: Any, registers: Any, import_row: dict[str, Any],
                             mapped_ranges: list[tuple[int, int]],
                             state: dict[str, Any]) -> bool:
    """Implement the bounded, single guest-thread critical-section contract.

    The guest-visible 24-byte structure is authoritative and checked against
    the oracle's ownership metadata on every operation. Contention cannot be
    scheduled by this startup runner, so EnterCriticalSection stops explicitly
    instead of reporting a successful or fabricated blocking operation.
    """
    name = import_row["name"]
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api = {
        "library": import_row["library"],
        "name": name,
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
    }
    state["api_calls"].append(api)

    def stop_state(reason: str, pointer: int, **details: Any) -> bool:
        api["outcome"] = "invalid_state"
        api["state_error"] = reason
        api.update(details)
        state["status"] = "GUEST_STOP_API_STATE"
        state["target"] = pointer & 0xFFFFFFFF
        state["api_state_fault"] = {
            "api": name,
            "address": pointer & 0xFFFFFFFF,
            "reason": reason,
            **details,
        }
        return False

    try:
        if not _range_is_mapped(esp, 8, mapped_ranges):
            raise _GuestPointerFault("read", esp, 8)
        return_address = _read_u32(engine, esp)
        pointer = _read_u32(engine, esp + 4)
        api["return_address"] = return_address
        api["argument"] = pointer
        api["address"] = pointer

        if not _range_is_mapped(pointer, CRITICAL_SECTION_SIZE, mapped_ranges):
            raise _GuestPointerFault("read_write", pointer, CRITICAL_SECTION_SIZE)

        sections: dict[int, dict[str, int]] = state["critical_sections"]
        section = sections.get(pointer)
        words = list(struct.unpack("<6I", engine.mem_read(pointer, CRITICAL_SECTION_SIZE)))

        if name == "InitializeCriticalSection":
            if section is not None:
                return stop_state("critical_section_already_initialized", pointer)
            if len(sections) >= CRITICAL_SECTION_MAX_COUNT:
                return stop_state("critical_section_limit", pointer,
                                  critical_section_count=len(sections))
            for other_address in sections:
                if pointer < other_address + CRITICAL_SECTION_SIZE and other_address < pointer + CRITICAL_SECTION_SIZE:
                    return stop_state("critical_section_overlap", pointer,
                                      other_address=other_address)
            initial_words = [0, 0xFFFFFFFF, 0, 0, 0, 0]
            engine.mem_write(pointer, struct.pack("<6I", *initial_words))
            sections[pointer] = {
                "lock_count": 0xFFFFFFFF,
                "recursion_count": 0,
                "owning_thread": 0,
            }
            api["outcome"] = "initialized"
            api["critical_section"] = dict(sections[pointer])
        else:
            if section is None:
                return stop_state("critical_section_not_initialized", pointer)
            expected_words = [
                0,
                section["lock_count"],
                section["recursion_count"],
                section["owning_thread"],
                0,
                0,
            ]
            if words != expected_words:
                return stop_state("critical_section_memory_mismatch", pointer,
                                  expected_words=expected_words,
                                  actual_words=words)

            owner = section["owning_thread"]
            recursion = section["recursion_count"]
            lock_count = section["lock_count"]
            if recursion == 0:
                if owner != 0 or lock_count != 0xFFFFFFFF:
                    return stop_state("invalid_unowned_critical_section", pointer,
                                      owner=owner, recursion_count=recursion,
                                      lock_count=lock_count)
            elif owner == 0 or lock_count != recursion - 1:
                return stop_state("invalid_owned_critical_section", pointer,
                                  owner=owner, recursion_count=recursion,
                                  lock_count=lock_count)

            if name in ("EnterCriticalSection", "TryEnterCriticalSection"):
                thread_id_address = TEB_BASE + TEB_THREAD_ID_OFFSET
                if not _range_is_mapped(thread_id_address, 4, mapped_ranges):
                    raise _GuestPointerFault("read", thread_id_address, 4)
                thread_id = _read_u32(engine, thread_id_address)
                if thread_id == 0:
                    return stop_state("invalid_current_thread_id", pointer)
                if owner not in (0, thread_id):
                    if name == "TryEnterCriticalSection":
                        api["outcome"] = "contended"
                        api["result"] = 0
                        api["critical_section"] = dict(section)
                    else:
                        return stop_state("critical_section_contention_unschedulable",
                                          pointer, owner=owner, thread_id=thread_id,
                                          recursion_count=recursion)
                else:
                    if recursion >= CRITICAL_SECTION_MAX_RECURSION:
                        return stop_state("critical_section_recursion_overflow", pointer,
                                          recursion_count=recursion)
                    recursion += 1
                    owner = thread_id
                    lock_count = recursion - 1
                    section.update(lock_count=lock_count,
                                   recursion_count=recursion,
                                   owning_thread=owner)
                    _write_u32(engine, pointer + 4, lock_count)
                    _write_u32(engine, pointer + 8, recursion)
                    _write_u32(engine, pointer + 12, owner)
                    api["outcome"] = "acquired"
                    api["critical_section"] = dict(section)
                    if name == "TryEnterCriticalSection":
                        api["result"] = 1
            elif name == "LeaveCriticalSection":
                thread_id_address = TEB_BASE + TEB_THREAD_ID_OFFSET
                if not _range_is_mapped(thread_id_address, 4, mapped_ranges):
                    raise _GuestPointerFault("read", thread_id_address, 4)
                thread_id = _read_u32(engine, thread_id_address)
                if thread_id == 0:
                    return stop_state("invalid_current_thread_id", pointer)
                if owner != thread_id or recursion == 0:
                    return stop_state("critical_section_leave_not_owned", pointer,
                                      owner=owner, thread_id=thread_id,
                                      recursion_count=recursion)
                recursion -= 1
                if recursion == 0:
                    owner = 0
                    lock_count = 0xFFFFFFFF
                else:
                    lock_count = recursion - 1
                section.update(lock_count=lock_count,
                               recursion_count=recursion,
                               owning_thread=owner)
                _write_u32(engine, pointer + 4, lock_count)
                _write_u32(engine, pointer + 8, recursion)
                _write_u32(engine, pointer + 12, owner)
                api["outcome"] = "released"
                api["critical_section"] = dict(section)
            elif name == "DeleteCriticalSection":
                if owner != 0 or recursion != 0 or lock_count != 0xFFFFFFFF:
                    return stop_state("critical_section_delete_owned", pointer,
                                      owner=owner, recursion_count=recursion,
                                      lock_count=lock_count)
                del sections[pointer]
                engine.mem_write(pointer, bytes(CRITICAL_SECTION_SIZE))
                api["outcome"] = "deleted"
                api["critical_section"] = dict(section)

        api["last_error_preserved"] = True
        api["flags_preserved"] = True
        if name == "TryEnterCriticalSection":
            engine.reg_write(registers.UC_X86_REG_EAX, int(api["result"]))
        # These are stdcall APIs with one pointer parameter. Void APIs leave
        # EAX untouched; EFLAGS and TEB.LastError are never written here.
        engine.reg_write(registers.UC_X86_REG_ESP, esp + 8)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api["esp_after"] = (esp + 8) & 0xFFFFFFFF
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _tls_import(engine: Any, registers: Any, unicorn_module: Any,
                import_row: dict[str, Any], mapped_ranges: list[tuple[int, int]],
                state: dict[str, Any]) -> bool:
    """Model the bounded 32-bit dynamic TLS APIs against guest TEB slot bytes.

    The process allocation bitmap is oracle state; each registered thread's
    values live in its x86 TEB TlsSlots[64] at +0xe10. Static PE TLS remains
    separate at ThreadLocalStoragePointer (+0x2c). Invalid/unallocated keys
    are strict API_STATE stops for this emulator contract.
    """
    name = import_row["name"]
    if name not in TLS_IMPORTS:
        return False
    argc = BOUNDARY_ARGUMENT_COUNTS[name]
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    api: dict[str, Any] = {
        "library": import_row["library"],
        "name": name,
        "import_index": import_row["index"],
        "tag": IMPORT_BASE + import_row["index"],
        "call_ip": state["last_ip"],
        "esp_before": esp,
        "argument_count": argc,
    }
    state["api_calls"].append(api)

    def stop_state(reason: str, address: int, **details: Any) -> bool:
        api["outcome"] = "invalid_state"
        api["state_error"] = reason
        api.update(details)
        state["status"] = "GUEST_STOP_API_STATE"
        state["target"] = address & 0xFFFFFFFF
        state["api_state_fault"] = {
            "api": name,
            "address": address & 0xFFFFFFFF,
            "reason": reason,
            **details,
        }
        return False

    def require_range(address: int, size: int, permissions: int,
                      access: str) -> None:
        if not _range_has_permissions(engine, address, size, permissions,
                                      mapped_ranges):
            raise _GuestPointerFault(access, min(max(address, 0), 0xFFFFFFFF), size)

    def checked_address(base: int, offset: int, size: int, access: str) -> int:
        address = base + offset
        if (base < 0 or base > 0xFFFFFFFF or address > 0xFFFFFFFF or
                size <= 0 or size > 0x100000000 - address):
            raise _GuestPointerFault(access, min(max(address, 0), 0xFFFFFFFF), size)
        return address

    def write_fault(address: int, size: int) -> None:
        require_range(address, size,
                      unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE,
                      "read_write")

    try:
        frame_size = 4 * (argc + 1)
        require_range(esp, frame_size, unicorn_module.UC_PROT_READ, "read")
        return_address = _read_u32(engine, esp)
        arguments = [_read_u32(engine, esp + 4 * (i + 1)) for i in range(argc)]
        api["return_address"] = return_address
        api["arguments"] = arguments

        teb = int(state.get("tls_current_teb", TEB_BASE))
        last_error_address = checked_address(teb, LAST_ERROR_OFFSET, 4, "read_write")
        # LastError is preflighted before any possible TLS mutation. Successful
        # GetValue writes zero; other success paths preserve its current value.
        write_fault(last_error_address, 4)
        last_error_before = _read_u32(engine, last_error_address)

        bitmap = int(state.get("tls_allocated_bitmap", 0))
        slot_count = int(state.get("tls_slot_count", bitmap.bit_count()))
        threads_obj = state.get("tls_threads", {})
        if (not isinstance(threads_obj, dict) or bitmap < 0 or
                bitmap >> TLS_SLOT_COUNT or slot_count != bitmap.bit_count()):
            return stop_state("tls_process_state_invalid", teb,
                              allocated_bitmap=bitmap, slot_count=slot_count)
        threads = dict(threads_obj)
        if len(threads) > TLS_MAX_THREAD_COUNT:
            return stop_state("tls_thread_limit", teb,
                              thread_count=len(threads))
        if teb == 0:
            return stop_state("tls_current_teb_invalid", teb)
        for base, registered_id in threads.items():
            if (not isinstance(base, int) or not isinstance(registered_id, int) or
                    base < 0 or base > 0xFFFFFFFF or registered_id <= 0 or
                    registered_id > 0xFFFFFFFF):
                return stop_state("tls_thread_registry_invalid", teb)

        # Match guest_tls_apply's failure ordering: basic set/count validation,
        # then key validation, then TEB identity and thread registration. In
        # particular, an invalid key does not probe TEB+0x24 first.
        index = arguments[0] if arguments else None
        value = arguments[1] if name == "TlsSetValue" else None
        api["index"] = index
        if name != "TlsAlloc":
            if int(index) >= TLS_SLOT_COUNT:
                return stop_state("tls_index_out_of_range", int(index),
                                  tls_slot_limit=TLS_SLOT_COUNT)
            if not (bitmap & (1 << int(index))):
                return stop_state("tls_index_not_allocated", int(index),
                                  allocated_bitmap=bitmap)

        thread_id_address = checked_address(teb, TEB_THREAD_ID_OFFSET, 4, "read")
        require_range(thread_id_address, 4, unicorn_module.UC_PROT_READ, "read")
        thread_id = _read_u32(engine, thread_id_address)
        api.update(teb=teb, thread_id=thread_id,
                   last_error_before=last_error_before)
        if thread_id == 0:
            return stop_state("tls_current_thread_id_invalid", thread_id_address)
        # guest_tls_apply requires the complete dynamic slot vector to fit in
        # the x86 address space, including for an already registered TEB.
        slots_address = checked_address(teb, TEB_TLS_SLOTS_OFFSET,
                                        TLS_SLOT_BYTES, "read_write")

        current_registered = teb in threads
        if current_registered and threads[teb] != thread_id:
            return stop_state("tls_thread_identity_changed", thread_id_address,
                              registered_thread_id=threads[teb],
                              current_thread_id=thread_id)
        if not current_registered:
            if thread_id in threads.values():
                return stop_state("tls_thread_id_alias", thread_id_address,
                                  thread_id=thread_id)
            if any(teb < base + 0x1000 and base < teb + 0x1000
                   for base in threads):
                return stop_state("tls_thread_teb_overlap", teb)
            if len(threads) >= TLS_MAX_THREAD_COUNT:
                if name == "TlsAlloc":
                    api.update(outcome="exhausted", result=0xFFFFFFFF,
                               error=ERROR_NOT_ENOUGH_MEMORY,
                               last_error_after=ERROR_NOT_ENOUGH_MEMORY,
                               tls_slot_count=slot_count,
                               tls_thread_count=len(threads),
                               exhaustion="thread_limit")
                    _write_u32(engine, last_error_address, ERROR_NOT_ENOUGH_MEMORY)
                    engine.reg_write(registers.UC_X86_REG_EAX, 0xFFFFFFFF)
                    engine.reg_write(registers.UC_X86_REG_ESP, esp + frame_size)
                    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
                    api["esp_after"] = (esp + frame_size) & 0xFFFFFFFF
                    state["resume"] = True
                    return True
                return stop_state("tls_thread_limit", teb,
                                  thread_count=len(threads))

        allocated_index: int | None = None
        if name == "TlsAlloc":
            allocated_index = next((i for i in range(TLS_SLOT_COUNT)
                                    if not (bitmap & (1 << i))), None)
            if allocated_index is None:
                result = 0xFFFFFFFF
                last_error_after = ERROR_NOT_ENOUGH_MEMORY
                _write_u32(engine, last_error_address, last_error_after)
                api.update(outcome="exhausted", result=result,
                           error=last_error_after,
                           last_error_after=last_error_after,
                           tls_slot_count=slot_count,
                           tls_thread_count=len(threads))
                engine.reg_write(registers.UC_X86_REG_EAX, result)
                engine.reg_write(registers.UC_X86_REG_ESP, esp + frame_size)
                engine.reg_write(registers.UC_X86_REG_EIP, return_address)
                api["esp_after"] = (esp + frame_size) & 0xFFFFFFFF
                state["resume"] = True
                return True

        # Any operation which registers a new guest thread initializes its
        # whole dynamic TLS vector. Existing threads are validated before the
        # first write so alloc/free cannot leave a partially reset population.
        if not current_registered:
            write_fault(slots_address, TLS_SLOT_BYTES)
        elif name in ("TlsGetValue", "TlsSetValue"):
            selected = checked_address(teb, TEB_TLS_SLOTS_OFFSET + 4 * int(index),
                                       4, "read_write" if name == "TlsSetValue" else "read")
            need = (unicorn_module.UC_PROT_READ | unicorn_module.UC_PROT_WRITE
                    if name == "TlsSetValue" else unicorn_module.UC_PROT_READ)
            require_range(selected, 4, need,
                          "read_write" if name == "TlsSetValue" else "read")

        selected_addresses: list[int] = []
        if name in ("TlsAlloc", "TlsFree"):
            reset_index = allocated_index if name == "TlsAlloc" else int(index)
            for base, registered_id in sorted(threads.items()):
                tid_address = checked_address(base, TEB_THREAD_ID_OFFSET, 4, "read")
                require_range(tid_address, 4, unicorn_module.UC_PROT_READ, "read")
                if _read_u32(engine, tid_address) != registered_id:
                    return stop_state("tls_thread_identity_changed", tid_address,
                                      registered_thread_id=registered_id)
                selected = checked_address(base,
                                           TEB_TLS_SLOTS_OFFSET + 4 * reset_index,
                                           4, "read_write")
                write_fault(selected, 4)
                selected_addresses.append(selected)

        # Commit only after every memory range and state constraint above has
        # been checked. New TEB slots are zeroed before storing the requested
        # value; 32-bit TLS values are opaque and are never dereferenced.
        if not current_registered:
            engine.mem_write(slots_address, bytes(TLS_SLOT_BYTES))
            threads[teb] = thread_id

        result: int
        if name == "TlsAlloc":
            assert allocated_index is not None
            for address in selected_addresses:
                _write_u32(engine, address, 0)
            bitmap |= 1 << allocated_index
            slot_count += 1
            result = allocated_index
            outcome = "allocated"
            api["allocated_index"] = allocated_index
            last_error_after = last_error_before
        elif name == "TlsFree":
            for address in selected_addresses:
                _write_u32(engine, address, 0)
            bitmap &= ~(1 << int(index))
            slot_count -= 1
            result = 1
            outcome = "freed"
            last_error_after = last_error_before
        elif name == "TlsSetValue":
            selected = checked_address(teb, TEB_TLS_SLOTS_OFFSET + 4 * int(index),
                                       4, "read_write")
            _write_u32(engine, selected, int(value))
            result = 1
            outcome = "stored"
            api["value"] = int(value)
            last_error_after = last_error_before
        else:  # TlsGetValue
            selected = checked_address(teb, TEB_TLS_SLOTS_OFFSET + 4 * int(index),
                                       4, "read")
            result = _read_u32(engine, selected)
            outcome = "retrieved"
            last_error_after = 0
            _write_u32(engine, last_error_address, last_error_after)

        state["tls_allocated_bitmap"] = bitmap
        state["tls_slot_count"] = slot_count
        state["tls_threads"] = threads
        api.update(outcome=outcome, result=result,
                   last_error_after=last_error_after,
                   tls_slot_count=slot_count,
                   tls_thread_count=len(threads))
        if name == "TlsFree":
            api["freed_index"] = int(index)
        if name in ("TlsGetValue", "TlsSetValue"):
            api["slot_address"] = teb + TEB_TLS_SLOTS_OFFSET + 4 * int(index)

        engine.reg_write(registers.UC_X86_REG_EAX, result)
        engine.reg_write(registers.UC_X86_REG_ESP, esp + frame_size)
        engine.reg_write(registers.UC_X86_REG_EIP, return_address)
        api["esp_after"] = (esp + frame_size) & 0xFFFFFFFF
        state["resume"] = True
        return True
    except _GuestPointerFault as exc:
        access, address, size = exc.args
        api["outcome"] = "invalid_pointer"
        api["fault"] = {"access": access, "address": int(address), "size": int(size)}
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = dict(api["fault"])
        return False


def _write_u32(engine: Any, address: int, value: int) -> None:
    engine.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", "replace")
    return str(value)


def _import_fields(item: Any) -> tuple[int, str, str]:
    """Accept the generator's dict rows, GuestImport-like objects, or triples."""
    if isinstance(item, Mapping):
        iat = item.get("iat", item.get("iat_address", item.get("address")))
        library = item.get("library", item.get("dll"))
        name = item.get("name", item.get("symbol"))
    elif isinstance(item, (tuple, list)) and len(item) == 3:
        iat, library, name = item
    else:
        iat = getattr(item, "iat", getattr(item, "iat_address", None))
        library = getattr(item, "library", getattr(item, "dll", None))
        name = getattr(item, "name", getattr(item, "symbol", None))
    if iat is None or library is None or name is None:
        raise ValueError("each import must provide iat, library, and name")
    address = int(iat)
    if not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("import IAT address is outside PE32 address space")
    return address, _as_text(library), _as_text(name)


def _pe_imports(pe: Any) -> list[tuple[int, str, str]]:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        raise ValueError("the executable has no parsed import table")
    rows = []
    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        library = descriptor.dll.decode("ascii", "replace")
        for imported in descriptor.imports:
            name = (imported.name.decode("ascii", "replace") if imported.name
                    else f"#{imported.ordinal}")
            rows.append((int(imported.address), library, name))
    return rows


def _validate_imports(pe_rows: list[tuple[int, str, str]], supplied: list[Any]) -> list[dict[str, Any]]:
    rows = [_import_fields(item) for item in supplied]
    if len(rows) != len(pe_rows):
        raise ValueError(f"import list is incomplete: PE={len(pe_rows)} supplied={len(rows)}")
    expected = {iat: (library.casefold(), name) for iat, library, name in pe_rows}
    if len(expected) != len(pe_rows):
        raise ValueError("PE import table contains duplicate IAT addresses")
    seen: set[int] = set()
    normalized = []
    for index, (iat, library, name) in enumerate(rows):
        if iat in seen:
            raise ValueError(f"duplicate IAT address in import list: 0x{iat:08x}")
        seen.add(iat)
        if expected.get(iat) != (library.casefold(), name):
            raise ValueError(f"import metadata does not match PE at IAT 0x{iat:08x}")
        normalized.append({"index": index, "iat": iat, "library": library, "name": name})
    if seen != set(expected):
        raise ValueError("import list does not cover the PE import table")
    return normalized


def _loader_image(pe: Any, blob: bytes) -> bytearray:
    """Mirror runtime/guest_pe.c: zero SizeOfImage, copy headers, then min(raw, VS)."""
    size = int(pe.OPTIONAL_HEADER.SizeOfImage)
    headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if not size or size > 64 * 1024 * 1024 or not headers or headers > size or headers > len(blob):
        raise ValueError("PE image/header sizes are outside the native loader limits")
    image = bytearray(size)
    image[:headers] = blob[:headers]
    for section in pe.sections:
        virtual_size = int(section.Misc_VirtualSize) or int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        raw_offset = int(section.PointerToRawData)
        copied = min(virtual_size, raw_size)
        if (virtual_address > size or virtual_size > size - virtual_address or
                raw_offset > len(blob) or copied > len(blob) - raw_offset):
            raise ValueError("PE section bounds disagree with the native loader")
        if copied:
            image[virtual_address:virtual_address + copied] = blob[raw_offset:raw_offset + copied]
    return image


def _segment_descriptor(base: int, access: int) -> bytes:
    limit = 0xFFFFF
    return struct.pack(
        "<HHBBBB",
        limit & 0xFFFF,
        base & 0xFFFF,
        (base >> 16) & 0xFF,
        access,
        ((limit >> 16) & 0x0F) | 0xC0,  # page granularity, 32-bit segment
        (base >> 24) & 0xFF,
    )


def _register_id(registers: Any, name: str) -> int:
    mapping = {
        "eax": registers.UC_X86_REG_EAX,
        "ecx": registers.UC_X86_REG_ECX,
        "edx": registers.UC_X86_REG_EDX,
        "ebx": registers.UC_X86_REG_EBX,
        "esp": registers.UC_X86_REG_ESP,
        "ebp": registers.UC_X86_REG_EBP,
        "esi": registers.UC_X86_REG_ESI,
        "edi": registers.UC_X86_REG_EDI,
    }
    return mapping[name]


def _is_rep_continuation(state: dict, address: int, mnemonic: str) -> bool:
    """Unicorn reports REP micro-iterations, including the final ECX=0 hook.

    The native step hook records the architectural instruction once. Only
    consecutive callbacks at the same REP IP are coalesced; all original x86
    iterations still execute, and branching back starts a new instruction.
    """
    repeated = mnemonic.split()[0] in ("rep", "repe", "repz", "repne", "repnz")
    continuation = repeated and state.get("rep_ip") == address
    state["rep_ip"] = address if repeated else None
    return continuation


def run_startup_reference(exe: Path, imports: list, *, diagnostic_directory: Path | None = None) -> dict[str, Any]:
    """Run the exact PE entry until its first unimplemented import thunk.

    `imports` is the same ordered list passed to the native IAT binder.  Each
    row can be a mapping with `iat`/`library`/`name`, an object with those
    attributes, or a three-item `(iat, library, name)` tuple.  The returned
    status must be `GUEST_STOP_IMPORT`; other stops raise so a changed startup
    path cannot silently become a successful oracle.
    """
    try:
        import pefile
        import unicorn as uc
        from unicorn import x86_const as xr
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError as exc:  # pragma: no cover - build host dependency failure
        raise RuntimeError("startup oracle requires build-host pefile, Capstone, and Unicorn") from exc

    path = Path(exe)
    blob = path.read_bytes()
    import hashlib
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != SUPPORTED_EXE_SIZE or digest != SUPPORTED_EXE_SHA256:
        raise ValueError("unsupported executable; startup oracle did not run")
    pe = pefile.PE(data=blob, fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if image_base != IMAGE_BASE or entry != ENTRY_POINT or int(pe.FILE_HEADER.Machine) != 0x14C:
        raise ValueError("authenticated executable layout changed")

    pe_rows = _pe_imports(pe)
    import_rows = _validate_imports(pe_rows, imports)
    index_by_iat = {row["iat"]: row["index"] for row in import_rows}
    first_expected = next((row for row in import_rows
                           if row["iat"] == 0x00783168), None)
    if not first_expected or first_expected["library"].casefold() != "kernel32.dll" or first_expected["name"] != "GetVersionExA":
        raise ValueError("the first startup import is not the expected GetVersionExA slot")

    image = _loader_image(pe, blob)
    image_size = len(image)
    page_size = 0x1000
    map_size = (image_size + page_size - 1) & ~(page_size - 1)
    engine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
    engine.mem_map(image_base, map_size, uc.UC_PROT_ALL)
    engine.mem_write(image_base, bytes(image))
    engine.mem_map(TEB_BASE, TEB_SIZE, uc.UC_PROT_ALL)
    engine.mem_map(STACK_LO, STACK_SIZE, uc.UC_PROT_ALL)
    # The import tags are executable stop sentinels. Unicorn requests a code
    # page before issuing its code hook, so map their page as inert zeroes.
    # The hook stops at the tag before any byte in this page is executed.
    engine.mem_map(IMPORT_BASE, page_size, uc.UC_PROT_ALL)

    # Unicorn does not provide a usable FS_BASE register in 32-bit mode.
    # Install flat 32-bit GDT segments so actual FS:[0] accesses reach the TEB.
    gdt_base = 0x10000000
    engine.mem_map(gdt_base, page_size, uc.UC_PROT_ALL)
    engine.mem_write(gdt_base + 8, _segment_descriptor(0, 0x9A))
    engine.mem_write(gdt_base + 16, _segment_descriptor(0, 0x92))
    engine.mem_write(gdt_base + 24, _segment_descriptor(TEB_BASE, 0x92))
    engine.reg_write(xr.UC_X86_REG_GDTR, (0, gdt_base, 0x1F, 0))
    for register, selector in (
        (xr.UC_X86_REG_CS, 0x08),
        (xr.UC_X86_REG_SS, 0x10),
        (xr.UC_X86_REG_DS, 0x10),
        (xr.UC_X86_REG_ES, 0x10),
        (xr.UC_X86_REG_FS, 0x18),
        (xr.UC_X86_REG_GS, 0x18),
    ):
        engine.reg_write(register, selector)

    # Match tests/boot.c. The PEB is inside this zeroed 0x20000-byte region.
    teb = bytearray(TEB_SIZE)
    for address, value in (
        (0x00, 0xFFFFFFFF),
        (0x04, STACK_HI),
        (0x08, STACK_LO),
        (0x18, TEB_BASE),
        (0x20, 100),
        (0x24, 1),
        (0x2C, TEB_BASE + 0x1000),
        (0x30, PEB_BASE),
        (PEB_BASE - TEB_BASE + 0x08, image_base),
        (PEB_BASE - TEB_BASE + 0xA4, 5),
        (PEB_BASE - TEB_BASE + 0xA8, 1),
    ):
        struct.pack_into("<I", teb, address, value)
    engine.mem_write(TEB_BASE, bytes(teb))

    process_state = _initialize_process_arena(engine, image_base, image_size, uc)

    # The native loader starts with zeroed committed pages and the same return
    # sentinel that tests/boot.c pushes before calling the entry function.
    start_esp = INITIAL_ESP - 4
    engine.mem_write(start_esp, struct.pack("<I", ENTRY_RETURN))
    engine.reg_write(xr.UC_X86_REG_ESP, start_esp)
    engine.reg_write(xr.UC_X86_REG_EBP, 0)
    engine.reg_write(xr.UC_X86_REG_EFLAGS, EFLAGS_INITIAL)
    if hasattr(xr, "UC_X86_REG_FPCW"):
        engine.reg_write(xr.UC_X86_REG_FPCW, FCW_INITIAL)
    engine.reg_write(xr.UC_X86_REG_EIP, entry)

    # Bind every import to the exact sentinel/index order used by native code.
    for row in import_rows:
        sentinel = IMPORT_BASE + row["index"]
        if sentinel > 0xFFFFFFFF:
            raise ValueError("import sentinel overflows PE32 address space")
        image_offset = row["iat"] - image_base
        if image_offset < 0 or image_offset + 4 > image_size:
            raise ValueError(f"IAT is outside the mapped image: 0x{row['iat']:08x}")
        struct.pack_into("<I", image, image_offset, sentinel)
        engine.mem_write(row["iat"], struct.pack("<I", sentinel))

    mapped_ranges = [
        (image_base, image_base + image_size),
        (TEB_BASE, TEB_BASE + TEB_SIZE),
        (PROCESS_BASE, PROCESS_BASE + PROCESS_COMMITTED_SIZE),
        (STACK_LO, STACK_HI),
    ]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    state: dict[str, Any] = {
        "status": None,
        "last_ip": 0,
        "instructions": 0,
        "calls": 1,  # guest_execution_run dispatches the entry function itself.
        "depth": 1,
        "maximum_depth": 1,
        "trace_hash": FNV64_OFFSET,
        "raw_instructions": 0,
        "raw_trace_hash": FNV64_OFFSET,
        "direct_calls": [],
        "indirect_jumps": [],
        "cpuid_calls": [],
        "import": None,
        "api_calls": [],
        "boundary_call": None,
        "heaps": {},
        "critical_sections": {},
        "tls_allocated_bitmap": 0,
        "tls_slot_count": 0,
        "tls_threads": {TEB_BASE: 1},
        "tls_current_teb": TEB_BASE,
        "process": process_state,
        "unhandled_exception_filter": 0,
        "resume": False,
        "memory_fault": None,
    }

    def stop_at_import(address: int) -> bool:
        if address < IMPORT_BASE:
            return False
        index = address - IMPORT_BASE
        if index >= len(import_rows):
            state["status"] = "GUEST_STOP_UNRESOLVED"
            state["target"] = address
        else:
            row = import_rows[index]
            api_key = (row["library"].casefold(), row["name"])
            if api_key in SUPPORTED_IMPORTS:
                if row["name"] == "RegOpenKeyA":
                    from registry_oracle import _registry_import
                    handled = _registry_import(engine, xr, uc, row, mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr, mapped_ranges, state)
                elif row["name"] == "GetWindowRect":
                    from window_oracle import _window_query_import
                    handled = _window_query_import(engine, xr, uc, row, mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr, mapped_ranges, state)
                elif row["name"] == "IsProcessorFeaturePresent":
                    handled = _is_processor_feature_present(engine, xr, uc, row, mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr, mapped_ranges, state)
                elif row["name"] == "GetVersionExA":
                    _get_version_ex_a(engine, xr, row, mapped_ranges, state)
                elif row["name"] == "GetModuleHandleA":
                    _get_module_handle_a(engine, xr, row, mapped_ranges, image_base, state)
                elif row["name"] == "GetStartupInfoA":
                    handled = _get_startup_info_a(engine, xr, uc, row,
                                                  mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetStdHandle":
                    handled = _get_std_handle(engine, xr, uc, row,
                                              mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetFileType":
                    handled = _get_file_type(engine, xr, uc, row,
                                             mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "SetHandleCount":
                    handled = _set_handle_count(engine, xr, uc, row,
                                                mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] in PROCESS_CODE_PAGES or row["name"] == "GetCommandLineA" or row["name"] in PROCESS_IMPORTS:
                    handled = _guest_process_import(engine, xr, uc, row,
                                                    mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetCurrentThreadId":
                    handled = _get_current_thread_id(engine, xr, uc, row,
                                                     mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] in TLS_IMPORTS:
                    handled = _tls_import(engine, xr, uc, row, mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] in CRITICAL_SECTION_IMPORTS:
                    handled = _critical_section_import(engine, xr, row,
                                                       mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "HeapCreate":
                    handled = _heap_create(engine, xr, uc, row,
                                           mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "HeapAlloc":
                    handled = _heap_alloc(engine, xr, uc, row,
                                          mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "HeapReAlloc":
                    handled = _heap_realloc(engine, xr, uc, row,
                                            mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "HeapFree":
                    handled = _heap_free(engine, xr, uc, row,
                                         mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "WideCharToMultiByte":
                    handled = _wide_char_to_multi_byte(engine, xr, uc, row,
                                                        mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetCPInfo":
                    handled = _get_cp_info(engine, xr, uc, row,
                                           mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetModuleFileNameA":
                    handled = _get_module_file_name_a(engine, xr, uc, row,
                                                      mapped_ranges, image_base, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetStringTypeW":
                    handled = _get_string_type_w(engine, xr, uc, row,
                                                 mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetStringTypeA":
                    handled = _get_string_type_a(engine, xr, uc, row,
                                                 mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "LCMapStringW":
                    handled = _lc_map_string_w(engine, xr, uc, row,
                                               mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "LCMapStringA":
                    handled = _lc_map_string_a(engine, xr, uc, row,
                                               mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "MultiByteToWideChar":
                    handled = _multi_byte_to_wide_char(engine, xr, uc, row,
                                                       mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "SetUnhandledExceptionFilter":
                    handled = _set_unhandled_exception_filter(engine, xr, uc, row,
                                                              mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "HeapSize":
                    handled = _heap_size(engine, xr, uc, row, mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetSystemTimeAsFileTime":
                    handled = _get_system_time_as_file_time(engine, xr, uc, row,
                                                            mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetCurrentProcessId":
                    handled = _get_current_process_id(engine, xr, uc, row,
                                                      mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "GetTickCount":
                    handled = _get_tick_count(engine, xr, uc, row,
                                              mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                elif row["name"] == "QueryPerformanceCounter":
                    handled = _query_performance_counter(engine, xr, uc, row,
                                                         mapped_ranges, state)
                    if handled or state["status"] is not None:
                        engine.emu_stop()
                        return True
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
                else:
                    _record_unsupported_import(address, index, row, engine, xr,
                                               mapped_ranges, state)
            else:
                _record_unsupported_import(address, index, row, engine, xr,
                                           mapped_ranges, state)
        engine.emu_stop()
        return True

    def _record_unsupported_import(address: int, index: int, row: dict[str, Any],
                                   uc_engine: Any, registers: Any,
                                   ranges: list[tuple[int, int]],
                                   current: dict[str, Any]) -> None:
        current["status"] = "GUEST_STOP_IMPORT"
        current["target"] = address
        current["import_index"] = index
        current["import"] = dict(row)
        argument_count = BOUNDARY_ARGUMENT_COUNTS.get(row["name"])
        if argument_count is None:
            return
        esp = int(uc_engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
        span = 4 * (argument_count + 1)
        if not _range_is_mapped(esp, span, ranges):
            current["status"] = "GUEST_STOP_MEMORY"
            current["target"] = esp
            current["memory_fault"] = {"access": "read", "address": esp, "size": span}
            return
        current["boundary_call"] = {
            "call_ip": current["last_ip"],
            "target": address,
            "import_index": index,
            "library": row["library"],
            "name": row["name"],
            "esp": esp,
            "return_address": _read_u32(uc_engine, esp),
            "arguments": [_read_u32(uc_engine, esp + 4 * i)
                          for i in range(1, argument_count + 1)],
        }

    regids = {name: _register_id(xr, name) for name in
              ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")}
    diagnostic_trace = bytearray()

    def on_code(uc_engine: Any, address: int, size: int, user_data: Any) -> None:
        if stop_at_import(address):
            return
        if address == 0x007646e5:
            # Match runtime/cpu.h eflags_get() by clearing bit 21 (ID flag)
            flags = uc_engine.reg_read(xr.UC_X86_REG_EFLAGS)
            uc_engine.reg_write(xr.UC_X86_REG_EFLAGS, (flags & EFLAGS_MASK) | 0x202)
        try:
            instruction = next(md.disasm(bytes(uc_engine.mem_read(address, min(size, 15))), address), None)
        except Exception:
            instruction = None
        if instruction is None:
            state["status"] = "GUEST_STOP_INSTRUCTION"
            state["target"] = address
            engine.emu_stop()
            return

        state["raw_instructions"] += 1
        state["raw_trace_hash"] = ((state["raw_trace_hash"] ^ address) * FNV64_PRIME) & FNV64_MASK
        if _is_rep_continuation(state, address, instruction.mnemonic):
            return
        if state["instructions"] >= INSTRUCTION_BUDGET:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = address
            engine.emu_stop()
            return
        state["last_ip"] = int(address) & 0xFFFFFFFF
        if diagnostic_directory is not None:
            diagnostic_trace.extend(struct.pack("<9I", address, *(
                int(uc_engine.reg_read(register)) & 0xFFFFFFFF for register in regids.values())))
        state["instructions"] += 1
        state["trace_hash"] = ((state["trace_hash"] ^ state["last_ip"]) * FNV64_PRIME) & FNV64_MASK

        if instruction.mnemonic == "cpuid":
            from cpuid_oracle import apply_cpuid
            apply_cpuid(uc_engine, xr, address, instruction.size, state)
            return

        if instruction.mnemonic in ("call", "jmp") and instruction.operands:
            is_call = instruction.mnemonic == "call"
            if is_call:
                state["calls"] += 1
            operand = instruction.operands[0]
            target = None
            if operand.type == X86_OP_IMM:
                target = int(operand.imm) & 0xFFFFFFFF
            elif operand.type == X86_OP_REG:
                target = int(uc_engine.reg_read(regids[instruction.reg_name(operand.reg)])) & 0xFFFFFFFF
            elif operand.type == X86_OP_MEM:
                memory = operand.mem
                effective = int(memory.disp) & 0xFFFFFFFF
                if memory.base:
                    effective = (effective + int(uc_engine.reg_read(regids[instruction.reg_name(memory.base)]))) & 0xFFFFFFFF
                if memory.index:
                    effective = (effective + int(uc_engine.reg_read(regids[instruction.reg_name(memory.index)])) * int(memory.scale)) & 0xFFFFFFFF
                segment = instruction.reg_name(memory.segment) if memory.segment else ""
                if segment == "fs":
                    effective = (effective + TEB_BASE) & 0xFFFFFFFF
                elif segment == "gs":
                    effective = (effective + TEB_BASE) & 0xFFFFFFFF
                try:
                    target = _read_u32(uc_engine, effective)
                except Exception:
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = effective
                    engine.emu_stop()
                    return
            if target is not None and target < IMPORT_BASE and IMAGE_BASE <= target < IMAGE_BASE + image_size:
                event = {"ip": int(address), "target": target}
                if is_call:
                    state["direct_calls"].append(event)
                    state["depth"] += 1
                    state["maximum_depth"] = max(state["maximum_depth"], state["depth"])
                elif operand.type != X86_OP_IMM and event not in state["indirect_jumps"]:
                    # Direct in-image jumps are already local CFG edges. Dynamic
                    # jumps need separately registered entries, without a CALL
                    # count/depth increment or a synthetic return frame.
                    state["indirect_jumps"].append(event)
            elif target is not None and target >= IMPORT_BASE:
                # The actual CALL executes after this hook and pushes its return
                # address. The code hook at the tagged destination stops before
                # any API body can run.
                state["pending_import_target"] = target

        if instruction.mnemonic in ("ret", "retf") and state["depth"] > 1:
            state["depth"] -= 1

    def on_unmapped(uc_engine: Any, access: int, address: int, size: int,
                    value: int, user_data: Any) -> bool:
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {"access": int(access), "address": int(address), "size": int(size)}
        engine.emu_stop()
        return False

    engine.hook_add(uc.UC_HOOK_CODE, on_code)
    engine.hook_add(uc.UC_HOOK_MEM_UNMAPPED, on_unmapped)
    begin = entry
    while state["status"] is None:
        remaining = INSTRUCTION_BUDGET - state["instructions"] + 1
        state["resume"] = False
        try:
            engine.emu_start(begin, 0, count=remaining)
        except Exception as exc:
            if state["status"] is None:
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
                state["emulator_error"] = f"{type(exc).__name__}: {exc}"
            break
        if state["status"] is not None:
            break
        if not state["resume"]:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
            break
        begin = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF

    if state["status"] != "GUEST_STOP_IMPORT":
        detail = state.get("api_state_fault", state.get("memory_fault"))
        raise RuntimeError(
            f"startup oracle stopped at {state.get('status')} "
            f"target=0x{state.get('target', 0):08x} detail={detail!r}"
        )
    boundary_import = state["import"]
    if (not state["api_calls"] or state["api_calls"][0]["name"] != "GetVersionExA" or
            state["api_calls"][0]["import_index"] != first_expected["index"]):
        raise RuntimeError("startup oracle did not execute the expected GetVersionExA boundary")
    boundary_key = (boundary_import["library"].casefold(), boundary_import["name"])
    if boundary_key in {
        ("kernel32.dll", "GetVersionExA"),
        ("kernel32.dll", "GetModuleHandleA"),
        ("kernel32.dll", "GetStartupInfoA"),
        ("kernel32.dll", "GetCurrentThreadId"),
        ("kernel32.dll", "SetHandleCount"),
        ("kernel32.dll", "GetCommandLineA"),
        *(('kernel32.dll', name) for name in PROCESS_IMPORTS),
        ("kernel32.dll", "GetACP"),
        ("kernel32.dll", "GetOEMCP"),
    } or (boundary_key in {
        ("kernel32.dll", "HeapCreate"),
        ("kernel32.dll", "HeapAlloc"),
        ("kernel32.dll", "HeapReAlloc"),
    } and not state["boundary_call"]):
        raise RuntimeError("startup oracle stopped at a supported import instead of applying its contract")
    if (boundary_key == ("kernel32.dll", "GetStdHandle") and
            (not state["boundary_call"] or
             not state["boundary_call"]["arguments"] or
             state["boundary_call"]["arguments"][0] in STD_HANDLE_SELECTORS)):
        raise RuntimeError("startup oracle stopped at a supported standard-handle selector")
    if (boundary_key == ("kernel32.dll", "GetFileType") and
            state["boundary_call"] and state["boundary_call"]["arguments"] and
            state["boundary_call"]["arguments"][0] in (0, 0xFFFFFFFF)):
        raise RuntimeError("startup oracle stopped at a supported invalid file handle")
    if boundary_key[0] == "kernel32.dll" and boundary_key[1] in CRITICAL_SECTION_IMPORTS:
        raise RuntimeError("startup oracle stopped at a supported critical-section import instead of applying its contract")
    if boundary_key[0] == "kernel32.dll" and boundary_key[1] in TLS_IMPORTS:
        raise RuntimeError("startup oracle stopped at a supported TLS import instead of applying its contract")

    # The guest runner's EIP is the last instruction reported by its step hook;
    # Unicorn's architectural EIP is the tagged import target after CALL.
    gprs = {name: int(engine.reg_read(registers)) & 0xFFFFFFFF
            for name, registers in regids.items()}
    architectural_eip = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
    eflags = int(engine.reg_read(xr.UC_X86_REG_EFLAGS)) & EFLAGS_MASK
    gprs["esp"] = int(engine.reg_read(xr.UC_X86_REG_ESP)) & 0xFFFFFFFF
    last_ip = state["last_ip"]
    stack_hash_start = max(STACK_LO, gprs["esp"] - STACK_WINDOW_BELOW)
    stack_hash_end = min(STACK_HI, stack_hash_start + STACK_WINDOW_SIZE)
    stack_window = bytes(engine.mem_read(stack_hash_start, stack_hash_end - stack_hash_start))
    image_state = bytes(engine.mem_read(image_base, image_size))
    teb_state = bytes(engine.mem_read(TEB_BASE, TEB_SIZE))
    process_hash_start = int(process_state["base"])
    process_hash_size = int(process_state["committed_size"])
    process_bytes = bytes(engine.mem_read(process_hash_start, process_hash_size))
    active_heaps = sorted(state["heaps"].values(), key=lambda heap: heap["slot"])
    active_critical_sections = [
        {"address": address, **dict(section)}
        for address, section in sorted(state["critical_sections"].items())
    ]
    heap_slots = []
    for slot in range(HEAP_MAX_COUNT):
        heap = state["heaps"].get(slot)
        if heap is None:
            heap_slots.append({"slot": slot, "handle": 0, "capacity": 0,
                               "fixed": False, "live_blocks": 0,
                               "blocks": []})
        else:
            heap_slots.append({"slot": slot, "handle": heap["handle"],
                               "capacity": heap["capacity"],
                               "fixed": bool(heap.get("fixed", False)),
                               "live_blocks": heap["live_blocks"],
                               "blocks": [dict(block) for block in heap["blocks"]]})
    if active_heaps:
        heap_hash_start = active_heaps[0]["handle"]
        heap_hash_size = active_heaps[0]["committed_size"]
        heap_state = bytes(engine.mem_read(heap_hash_start, heap_hash_size))
    else:
        heap_hash_start = 0
        heap_hash_size = 0
        heap_state = b""

    if diagnostic_directory is not None:
        # Private host diagnostics only. These snapshots never enter source
        # control, public Actions, or the iOS app bundle.
        directory = Path(diagnostic_directory)
        for label, data in (("trace", diagnostic_trace), ("image", image_state),
                            ("teb", teb_state), ("stack", stack_window),
                            ("heap", heap_state), ("process", process_bytes)):
            (directory / f"startup_{label}.bin").write_bytes(data)

    flags = {
        "cf": eflags & 0x001,
        "pf": (eflags >> 2) & 1,
        "af": (eflags >> 4) & 1,
        "zf": (eflags >> 6) & 1,
        "sf": (eflags >> 7) & 1,
        "df": (eflags >> 10) & 1,
        "of": (eflags >> 11) & 1,
    }
    cpu_state = {
        "r": [gprs[name] for name in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")],
        "gpr": gprs,
        "eip": last_ip,
        "fs_base": TEB_BASE,
        "gs_base": TEB_BASE,
        "eflags_masked": eflags,
        "flags": flags,
        "fcw": FCW_INITIAL,
        "fsw": 0,
        "top": 0,
        "st_f64_bits": [0] * 8,
        "mm": [0] * 8,
        "xmm_u64": [[0, 0] for _ in range(8)],
    }
    result = {
        "schema_version": 1,
        "reference": "Unicorn x86-32; authentic PE instructions with declared bounded KERNEL32 contracts",
        "executable_size": len(blob),
        "executable_sha256": digest,
        "image_base": image_base,
        "image_size": image_size,
        "entry_point": entry,
        "status": state["status"],
        "ip": last_ip,
        "target": int(state["target"]),
        "import_index": int(state["import_index"]),
        "import_iat": int(boundary_import["iat"]),
        "import_library": boundary_import["library"],
        "import_name": boundary_import["name"],
        "api_call_count": len(state["api_calls"]),
        "api_calls": state["api_calls"],
        "boundary_call": state["boundary_call"],
        "critical_section_count": len(active_critical_sections),
        "critical_sections": active_critical_sections,
        "tls_slot_count": int(state["tls_slot_count"]),
        "tls_thread_count": len(state["tls_threads"]),
        "process_state": dict(process_state),
        "state_heaps": heap_slots,
        "instructions": int(state["instructions"]),
        "calls": int(state["calls"]),
        "maximum_depth": int(state["maximum_depth"]),
        "trace_hash": int(state["trace_hash"]),
        "raw_instructions": int(state["raw_instructions"]),
        "raw_trace_hash": int(state["raw_trace_hash"]),
        "cpu": cpu_state,
        "unicorn_eip_at_stop": architectural_eip,
        "direct_calls": state["direct_calls"],
        "indirect_jumps": state["indirect_jumps"],
        "cpuid_profile": "upstream_static_x86_006d8",
        "cpuid_calls": state["cpuid_calls"],
        "image_hash_start": image_base,
        "image_hash_size": image_size,
        "image_hash64": _fnv1a64(image_state),
        "teb_hash_start": TEB_BASE,
        "teb_hash_size": TEB_SIZE,
        "teb_hash64": _fnv1a64(teb_state),
        "stack_hash_start": stack_hash_start,
        "stack_hash_size": len(stack_window),
        "stack_hash64": _fnv1a64(stack_window),
        "heap_hash_start": heap_hash_start,
        "heap_hash_size": heap_hash_size,
        "heap_hash64": _fnv1a64(heap_state),
        "process_hash_start": process_hash_start,
        "process_hash_size": process_hash_size,
        "process_hash64": _fnv1a64(process_bytes),
        "stack_base": STACK_LO,
        "stack_size": STACK_SIZE,
        "stack_initial_esp": start_esp,
    }
    return result
