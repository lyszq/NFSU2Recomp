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
INSTRUCTION_BUDGET = 100_000
STACK_WINDOW_BELOW = 0x1000
STACK_WINDOW_SIZE = 0x2000
LAST_ERROR_OFFSET = 0x34
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
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
TEB_THREAD_ID_OFFSET = 0x24
TEB_TLS_SLOTS_OFFSET = 0xE10
TLS_SLOT_COUNT = 64
TLS_SLOT_BYTES = TLS_SLOT_COUNT * 4
TLS_MAX_THREAD_COUNT = 64
TLS_IMPORTS = {"TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue"}
BOUNDARY_ARGUMENT_COUNTS = {
    "GetCurrentThreadId": 0,
    "TlsAlloc": 0,
    "TlsFree": 1,
    "TlsGetValue": 1,
    "TlsSetValue": 2,
    "HeapCreate": 3,
    "HeapAlloc": 3,
    "HeapFree": 3,
    "HeapSize": 3,
    "HeapDestroy": 1,
    "InitializeCriticalSection": 1,
    "EnterCriticalSection": 1,
    "TryEnterCriticalSection": 1,
    "LeaveCriticalSection": 1,
    "DeleteCriticalSection": 1,
}
CRITICAL_SECTION_IMPORTS = {
    "InitializeCriticalSection",
    "EnterCriticalSection",
    "TryEnterCriticalSection",
    "LeaveCriticalSection",
    "DeleteCriticalSection",
}
SUPPORTED_IMPORTS = {
    ("kernel32.dll", "GetVersionExA"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetCurrentThreadId"),
    ("kernel32.dll", "HeapCreate"),
    ("kernel32.dll", "HeapAlloc"),
    *(("kernel32.dll", name) for name in CRITICAL_SECTION_IMPORTS),
    *(("kernel32.dll", name) for name in TLS_IMPORTS),
}
ERROR_MOD_NOT_FOUND = 126


def _fnv1a64(data: bytes | bytearray | memoryview) -> int:
    value = FNV64_OFFSET
    for byte in memoryview(data).cast("B"):
        value = ((value ^ byte) * FNV64_PRIME) & FNV64_MASK
    return value


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


def run_startup_reference(exe: Path, imports: list) -> dict[str, Any]:
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
        "direct_calls": [],
        "import": None,
        "api_calls": [],
        "boundary_call": None,
        "heaps": {},
        "critical_sections": {},
        "tls_allocated_bitmap": 0,
        "tls_slot_count": 0,
        "tls_threads": {TEB_BASE: 1},
        "tls_current_teb": TEB_BASE,
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
                if row["name"] == "GetVersionExA":
                    _get_version_ex_a(engine, xr, row, mapped_ranges, state)
                elif row["name"] == "GetModuleHandleA":
                    _get_module_handle_a(engine, xr, row, mapped_ranges, image_base, state)
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

    def on_code(uc_engine: Any, address: int, size: int, user_data: Any) -> None:
        if stop_at_import(address):
            return
        if state["instructions"] >= INSTRUCTION_BUDGET:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = address
            engine.emu_stop()
            return
        try:
            instruction = next(md.disasm(bytes(uc_engine.mem_read(address, min(size, 15))), address), None)
        except Exception:
            instruction = None
        if instruction is None:
            state["status"] = "GUEST_STOP_INSTRUCTION"
            state["target"] = address
            engine.emu_stop()
            return

        state["last_ip"] = int(address) & 0xFFFFFFFF
        state["instructions"] += 1
        state["trace_hash"] = ((state["trace_hash"] ^ state["last_ip"]) * FNV64_PRIME) & FNV64_MASK

        if instruction.mnemonic == "call" and instruction.operands:
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
                state["direct_calls"].append({"ip": int(address), "target": target})
                state["depth"] += 1
                state["maximum_depth"] = max(state["maximum_depth"], state["depth"])
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
        ("kernel32.dll", "GetCurrentThreadId"),
    } or (boundary_key in {
        ("kernel32.dll", "HeapCreate"),
        ("kernel32.dll", "HeapAlloc"),
    } and not state["boundary_call"]):
        raise RuntimeError("startup oracle stopped at a supported import instead of applying its contract")
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
        "state_heaps": heap_slots,
        "instructions": int(state["instructions"]),
        "calls": int(state["calls"]),
        "maximum_depth": int(state["maximum_depth"]),
        "trace_hash": int(state["trace_hash"]),
        "cpu": cpu_state,
        "unicorn_eip_at_stop": architectural_eip,
        "direct_calls": state["direct_calls"],
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
        "stack_base": STACK_LO,
        "stack_size": STACK_SIZE,
        "stack_initial_esp": start_esp,
    }
    return result
