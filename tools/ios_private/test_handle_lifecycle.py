#!/usr/bin/env python3
"""Synthetic-memory and integration tests for handle lifecycle coordination.

Tests handle partition boundaries, non-overlap, and delegation logic for CloseHandle
across guest file, toolhelp snapshot, user object, and heap subsystems.
"""
from __future__ import annotations

from pathlib import Path
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(__file__).resolve().parent
for path in (ROOT / "tools", PRIVATE, ROOT / "out" / "private-deps"):
    if path.is_dir():
        sys.path.insert(0, str(path))

import unicorn
from unicorn import x86_const

from window_oracle import _memory_fault, _api_state_fault, _range_has_permissions


# ==============================================================================
# Architectural Constants & Handle Partition Definitions
# ==============================================================================

# KERNEL32 File Subsystem (runtime/guest_file.h)
GUEST_FILE_HANDLE_BASE = 0x00900000
GUEST_FILE_HANDLE_MAX = 1024
GUEST_FILE_HANDLE_MIN = GUEST_FILE_HANDLE_BASE + 1  # 0x00900001
GUEST_FILE_HANDLE_LIMIT = GUEST_FILE_HANDLE_BASE + GUEST_FILE_HANDLE_MAX  # 0x00900400 (exclusive)

# USER32 Object Subsystem (runtime/guest_user_objects.h)
GUEST_USER_OBJECT_HANDLE_BASE = 0x00B10000
GUEST_USER_OBJECT_LIMIT = 8
GUEST_USER_OBJECT_MIN = GUEST_USER_OBJECT_HANDLE_BASE + 1  # 0x00B10001
GUEST_USER_OBJECT_MAX = GUEST_USER_OBJECT_HANDLE_BASE + GUEST_USER_OBJECT_LIMIT  # 0x00B10008

# Process Environment & TEB (runtime/guest_process.h, guest_bootstrap.h)
GUEST_TEB_BASE = 0x00C00000
GUEST_PROCESS_BASE = 0x00C20000

# Toolhelp Snapshot Subsystem (runtime/guest_toolhelp.h)
GUEST_TOOLHELP_HANDLE_BASE = 0x00D10000
GUEST_TOOLHELP_HANDLE_MAX = 8
GUEST_TOOLHELP_HANDLE_MIN = GUEST_TOOLHELP_HANDLE_BASE + 1  # 0x00D10001
GUEST_TOOLHELP_HANDLE_MAX_VAL = GUEST_TOOLHELP_HANDLE_BASE + GUEST_TOOLHELP_HANDLE_MAX  # 0x00D10008

# Heap Subsystem (runtime/guest_heap.h)
GUEST_HEAP_BASE = 0x20000000
GUEST_HEAP_ARENA_SIZE = 0x04000000  # 64 MB
GUEST_HEAP_MAX_HEAPS = 4
GUEST_HEAP_LIMIT = GUEST_HEAP_BASE + (GUEST_HEAP_MAX_HEAPS * GUEST_HEAP_ARENA_SIZE)  # 0x30000000

# Standard Win32 Return / Error Codes
GUEST_INVALID_HANDLE_VALUE = 0xFFFFFFFF
ERROR_SUCCESS = 0
ERROR_INVALID_HANDLE = 6

# Guest Execution & TEB Fixtures
STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF000008E
IMPORT_INDEX = 142
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
LAST_ERROR_SENTINEL = 0x76543210

OTHER_REGISTERS = (
    x86_const.UC_X86_REG_EBX,
    x86_const.UC_X86_REG_ECX,
    x86_const.UC_X86_REG_EDX,
    x86_const.UC_X86_REG_ESI,
    x86_const.UC_X86_REG_EDI,
    x86_const.UC_X86_REG_EBP,
)

SNAPSHOT_REGISTERS = (
    x86_const.UC_X86_REG_EAX,
    x86_const.UC_X86_REG_EIP,
    x86_const.UC_X86_REG_ESP,
    x86_const.UC_X86_REG_EFLAGS,
) + OTHER_REGISTERS


# ==============================================================================
# Mock Subsystems Modeling Runtime Handle Ownership
# ==============================================================================

class MockFileSubsystem:
    """Models the guest file handle table (GuestFileTable)."""

    def __init__(self) -> None:
        self.open_handles: Set[int] = set()

    def alloc_handle(self, slot: int = 1) -> int:
        assert 1 <= slot < GUEST_FILE_HANDLE_MAX, f"Invalid file slot: {slot}"
        handle = GUEST_FILE_HANDLE_BASE + slot
        self.open_handles.add(handle)
        return handle

    @staticmethod
    def is_in_range(handle: int) -> bool:
        return GUEST_FILE_HANDLE_MIN <= handle < GUEST_FILE_HANDLE_LIMIT

    def close_handle(self, handle: int) -> Optional[bool]:
        """Returns True if closed, False if in range but not open, None if out of range."""
        if not self.is_in_range(handle):
            return None
        if handle in self.open_handles:
            self.open_handles.remove(handle)
            return True
        return False


class MockToolhelpSubsystem:
    """Models the guest toolhelp snapshot registry (GuestToolhelpSet)."""

    def __init__(self) -> None:
        self.active_snapshots: Set[int] = set()

    def alloc_snapshot(self, slot: int = 1) -> int:
        assert 1 <= slot <= GUEST_TOOLHELP_HANDLE_MAX, f"Invalid toolhelp slot: {slot}"
        handle = GUEST_TOOLHELP_HANDLE_BASE + slot
        self.active_snapshots.add(handle)
        return handle

    @staticmethod
    def is_in_range(handle: int) -> bool:
        return GUEST_TOOLHELP_HANDLE_MIN <= handle <= GUEST_TOOLHELP_HANDLE_MAX_VAL

    def close_handle(self, handle: int) -> Optional[bool]:
        """Returns True if closed, False if in range but not open, None if out of range."""
        if not self.is_in_range(handle):
            return None
        if handle in self.active_snapshots:
            self.active_snapshots.remove(handle)
            return True
        return False


class MockUserObjectsSubsystem:
    """Models the guest USER32 object table (GuestUserObjects)."""

    def __init__(self) -> None:
        self.objects: Dict[int, Dict[str, Any]] = {}

    def alloc_object(self, slot: int = 0, kind: str = "CURSOR") -> int:
        assert 0 <= slot < GUEST_USER_OBJECT_LIMIT, f"Invalid user object slot: {slot}"
        handle = GUEST_USER_OBJECT_HANDLE_BASE + slot + 1
        self.objects[handle] = {"handle": handle, "kind": kind}
        return handle

    @staticmethod
    def is_in_range(handle: int) -> bool:
        return GUEST_USER_OBJECT_MIN <= handle <= GUEST_USER_OBJECT_MAX


# ==============================================================================
# Lifecycle Dispatcher Emulating guest_windows CloseHandle Dispatch
# ==============================================================================

def _write_teb_last_error(engine: Any, state: Dict[str, Any], error_code: int,
                          mapped_ranges: List[Tuple[int, int]]) -> bool:
    """Writes error_code to TEB LastError offset 0x34 with strict fault preflight."""
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
            engine, last_error_address, 4, unicorn.UC_PROT_WRITE, mapped_ranges):
        _memory_fault(state, "write", last_error_address, 4)
        return False

    engine.mem_write(last_error_address, struct.pack("<I", error_code))
    return True


def _dispatch_close_handle(engine: Any, registers: Any, unicorn_module: Any,
                           row: Dict[str, Any],
                           file_subsystem: MockFileSubsystem,
                           toolhelp_subsystem: MockToolhelpSubsystem,
                           mapped_ranges: List[Tuple[int, int]],
                           state: Dict[str, Any]) -> bool:
    """Dispatches KERNEL32!CloseHandle according to the unified lifecycle architecture.

    Contract:
    - Stack frame: 8 bytes (argc 1, ret_addr + hObject).
    - If hObject in file handle range: delegated to file subsystem.
    - If hObject in toolhelp snapshot range: delegated to toolhelp subsystem.
    - Otherwise (alien, USER32 object, heap handle, sentinel): general handler fails.
    - On success: EAX = 1, ESP += 8, EIP = ret_addr. LastError is PRESERVED.
    - On failure: EAX = 0, ESP += 8, EIP = ret_addr. LastError is set to ERROR_INVALID_HANDLE (6).
    """
    library = str(row.get("library", ""))
    if library.casefold() != "kernel32.dll" or row.get("name") != "CloseHandle":
        return False

    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xFFFFFFFF
    if not _range_has_permissions(
            engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 8)
        return False

    frame = bytes(engine.mem_read(esp, 8))
    return_address, h_object = struct.unpack("<II", frame)

    # 1. Inspect and delegate to File Subsystem
    if file_subsystem.is_in_range(h_object):
        freed = file_subsystem.close_handle(h_object)
        if freed:
            # File handle closed successfully. Success preserves LastError.
            engine.reg_write(registers.UC_X86_REG_EAX, 1)
            engine.reg_write(registers.UC_X86_REG_EIP, return_address)
            engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
            state["resume"] = True
            return True
        else:
            # File handle within range but invalid / already closed
            if not _write_teb_last_error(engine, state, ERROR_INVALID_HANDLE, mapped_ranges):
                return False
            engine.reg_write(registers.UC_X86_REG_EAX, 0)
            engine.reg_write(registers.UC_X86_REG_EIP, return_address)
            engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
            state["resume"] = True
            return True

    # 2. Inspect and delegate to Toolhelp Subsystem
    if toolhelp_subsystem.is_in_range(h_object):
        freed = toolhelp_subsystem.close_handle(h_object)
        if freed:
            # Snapshot handle closed successfully. Success preserves LastError.
            engine.reg_write(registers.UC_X86_REG_EAX, 1)
            engine.reg_write(registers.UC_X86_REG_EIP, return_address)
            engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
            state["resume"] = True
            return True
        else:
            # Snapshot handle within range but invalid / already closed
            if not _write_teb_last_error(engine, state, ERROR_INVALID_HANDLE, mapped_ranges):
                return False
            engine.reg_write(registers.UC_X86_REG_EAX, 0)
            engine.reg_write(registers.UC_X86_REG_EIP, return_address)
            engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
            state["resume"] = True
            return True

    # 3. Alien or Non-delegable Subsystems (USER32 objects, Heaps, NULL, Sentinels)
    # The general KERNEL32 dispatcher rejects them with ERROR_INVALID_HANDLE (6).
    if not _write_teb_last_error(engine, state, ERROR_INVALID_HANDLE, mapped_ranges):
        return False

    engine.reg_write(registers.UC_X86_REG_EAX, 0)
    engine.reg_write(registers.UC_X86_REG_EIP, return_address)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xFFFFFFFF)
    state["resume"] = True
    return True


# ==============================================================================
# Unit Test Suite
# ==============================================================================

class TestHandlePartitionBoundaries(unittest.TestCase):
    """Verifies that all subsystem handle ranges are strictly non-overlapping and bounded."""

    def test_c_header_constants_match(self) -> None:
        """Asserts that Python constants match C header definitions in runtime/."""
        # 1. guest_file.h
        file_h = (ROOT / "runtime" / "guest_file.h").read_text(encoding="utf-8")
        base_match = re.search(r"#define\s+GUEST_FILE_HANDLE_BASE\s+UINT32_C\((0x[0-9a-fA-F]+)\)", file_h)
        self.assertIsNotNone(base_match)
        self.assertEqual(int(base_match.group(1), 16), GUEST_FILE_HANDLE_BASE)
        max_match = re.search(r"#define\s+GUEST_FILE_HANDLE_MAX\s+(\d+)", file_h)
        self.assertIsNotNone(max_match)
        self.assertEqual(int(max_match.group(1)), GUEST_FILE_HANDLE_MAX)

        # 2. guest_user_objects.h
        user_h = (ROOT / "runtime" / "guest_user_objects.h").read_text(encoding="utf-8")
        user_base = re.search(r"#define\s+GUEST_USER_OBJECT_HANDLE_BASE\s+UINT32_C\((0x[0-9a-fA-F]+)\)", user_h)
        self.assertIsNotNone(user_base)
        self.assertEqual(int(user_base.group(1), 16), GUEST_USER_OBJECT_HANDLE_BASE)
        user_limit = re.search(r"#define\s+GUEST_USER_OBJECT_LIMIT\s+(\d+)u?", user_h)
        self.assertIsNotNone(user_limit)
        self.assertEqual(int(user_limit.group(1)), GUEST_USER_OBJECT_LIMIT)

        # 3. guest_heap.h
        heap_h = (ROOT / "runtime" / "guest_heap.h").read_text(encoding="utf-8")
        heap_base = re.search(r"#define\s+GUEST_HEAP_BASE\s+(0x[0-9a-fA-F]+)u?", heap_h)
        self.assertIsNotNone(heap_base)
        self.assertEqual(int(heap_base.group(1), 16), GUEST_HEAP_BASE)
        arena_size = re.search(r"#define\s+GUEST_HEAP_ARENA_SIZE\s+(0x[0-9a-fA-F]+)u?", heap_h)
        self.assertIsNotNone(arena_size)
        self.assertEqual(int(arena_size.group(1), 16), GUEST_HEAP_ARENA_SIZE)
        max_heaps = re.search(r"#define\s+GUEST_HEAP_MAX_HEAPS\s+(\d+)", heap_h)
        self.assertIsNotNone(max_heaps)
        self.assertEqual(int(max_heaps.group(1)), GUEST_HEAP_MAX_HEAPS)

        # 4. guest_toolhelp.h
        toolhelp_h_path = ROOT / "runtime" / "guest_toolhelp.h"
        if toolhelp_h_path.is_file():
            toolhelp_h = toolhelp_h_path.read_text(encoding="utf-8")
            th_base = re.search(r"#define\s+GUEST_TOOLHELP_HANDLE_BASE\s+(0x[0-9a-fA-F]+)u?", toolhelp_h)
            self.assertIsNotNone(th_base)
            self.assertEqual(int(th_base.group(1), 16), GUEST_TOOLHELP_HANDLE_BASE)
            th_limit = re.search(r"#define\s+GUEST_TOOLHELP_SNAPSHOT_LIMIT\s+(\d+)u?", toolhelp_h)
            self.assertIsNotNone(th_limit)
            self.assertEqual(int(th_limit.group(1)), GUEST_TOOLHELP_HANDLE_MAX)

    def test_handle_partitions_disjoint(self) -> None:
        """Verifies pairwise disjointness between all handle domains."""
        file_range = range(GUEST_FILE_HANDLE_MIN, GUEST_FILE_HANDLE_LIMIT)
        user_range = range(GUEST_USER_OBJECT_MIN, GUEST_USER_OBJECT_MAX + 1)
        toolhelp_range = range(GUEST_TOOLHELP_HANDLE_MIN, GUEST_TOOLHELP_HANDLE_MAX_VAL + 1)
        heap_range = range(GUEST_HEAP_BASE, GUEST_HEAP_LIMIT, GUEST_HEAP_ARENA_SIZE)

        file_set = set(file_range)
        user_set = set(user_range)
        toolhelp_set = set(toolhelp_range)
        heap_set = set(heap_range)

        # Verify all pairwise intersections are empty
        self.assertEqual(file_set & user_set, set(), "File and User Object handles collide")
        self.assertEqual(file_set & toolhelp_set, set(), "File and Toolhelp handles collide")
        self.assertEqual(file_set & heap_set, set(), "File and Heap handles collide")
        self.assertEqual(user_set & toolhelp_set, set(), "User Object and Toolhelp handles collide")
        self.assertEqual(user_set & heap_set, set(), "User Object and Heap handles collide")
        self.assertEqual(toolhelp_set & heap_set, set(), "Toolhelp and Heap handles collide")

    def test_guard_intervals_between_partitions(self) -> None:
        """Verifies large positive guard distances between partitions."""
        self.assertGreater(GUEST_USER_OBJECT_MIN - GUEST_FILE_HANDLE_LIMIT, 0x00200000)
        self.assertGreater(GUEST_TEB_BASE - GUEST_USER_OBJECT_MAX, 0x000E0000)
        self.assertGreater(GUEST_TOOLHELP_HANDLE_MIN - GUEST_PROCESS_BASE, 0x000E0000)
        self.assertGreater(GUEST_HEAP_BASE - GUEST_TOOLHELP_HANDLE_MAX_VAL, 0x1F000000)

    def test_base_addresses_not_valid_handles(self) -> None:
        """Verifies that 0-indexed base values are outside the 1-based valid handle sets."""
        self.assertFalse(MockFileSubsystem.is_in_range(GUEST_FILE_HANDLE_BASE))
        self.assertFalse(MockToolhelpSubsystem.is_in_range(GUEST_TOOLHELP_HANDLE_BASE))
        self.assertFalse(MockUserObjectsSubsystem.is_in_range(GUEST_USER_OBJECT_HANDLE_BASE))


class TestHandleLifecycleBase(unittest.TestCase):
    """Base fixture for synthetic-memory lifecycle execution tests using Unicorn."""

    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + PAGE_SIZE),
        ]
        self.file_subsystem = MockFileSubsystem()
        self.toolhelp_subsystem = MockToolhelpSubsystem()
        self.user_objects = MockUserObjectsSubsystem()

        self.state: Dict[str, Any] = {
            "last_ip": IMPORT_IP,
            "resume": False,
            "status": None,
            "tls_current_teb": TEB_BASE,
        }
        self.row = {
            "library": "kernel32.dll",
            "name": "CloseHandle",
            "index": IMPORT_INDEX,
        }
        self._set_teb_last_error(LAST_ERROR_SENTINEL)

    def _set_teb_last_error(self, value: int) -> None:
        self.engine.mem_write(TEB_BASE + LAST_ERROR_OFFSET, struct.pack("<I", value))

    def _get_teb_last_error(self) -> int:
        data = bytes(self.engine.mem_read(TEB_BASE + LAST_ERROR_OFFSET, 4))
        return struct.unpack("<I", data)[0]

    def _setup_call_frame(self, h_object: int, esp: int = STACK_BASE + 0x800) -> int:
        frame = struct.pack("<II", RETURN_ADDRESS, h_object)
        self.engine.mem_write(esp, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for reg in OTHER_REGISTERS:
            self.engine.reg_write(reg, 0x11111111 * (reg + 1))
        return esp

    def _dispatch(self) -> bool:
        return _dispatch_close_handle(
            self.engine, x86_const, unicorn, self.row,
            self.file_subsystem, self.toolhelp_subsystem,
            self.mapped_ranges, self.state
        )

    def _snapshot_registers(self) -> Dict[int, int]:
        return {reg: int(self.engine.reg_read(reg)) for reg in SNAPSHOT_REGISTERS}


class TestFileHandleDelegation(TestHandleLifecycleBase):
    """Tests CloseHandle delegation to the guest file subsystem."""

    def test_close_single_open_file_success(self) -> None:
        handle = self.file_subsystem.alloc_handle(1)
        esp = self._setup_call_frame(handle)

        success = self._dispatch()
        self.assertTrue(success)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        # Success preserves pre-existing LastError
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)
        # Handle should now be freed
        self.assertNotIn(handle, self.file_subsystem.open_handles)

    def test_close_file_at_upper_bound(self) -> None:
        handle = self.file_subsystem.alloc_handle(GUEST_FILE_HANDLE_MAX - 1)
        self.assertEqual(handle, 0x009003FF)
        esp = self._setup_call_frame(handle)

        success = self._dispatch()
        self.assertTrue(success)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)
        self.assertNotIn(handle, self.file_subsystem.open_handles)

    def test_close_file_double_close_fails_with_invalid_handle(self) -> None:
        handle = self.file_subsystem.alloc_handle(5)
        esp = self._setup_call_frame(handle)

        # First close succeeds
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)

        # Second close of the same handle fails
        self._setup_call_frame(handle, esp)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

        # Third close also fails idempotently
        self._setup_call_frame(handle, esp)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_unallocated_file_handle_in_range_fails(self) -> None:
        unallocated_handle = GUEST_FILE_HANDLE_BASE + 42
        esp = self._setup_call_frame(unallocated_handle)

        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_multiple_file_handles_interleaved(self) -> None:
        h1 = self.file_subsystem.alloc_handle(1)
        h2 = self.file_subsystem.alloc_handle(2)
        h3 = self.file_subsystem.alloc_handle(3)

        # Close h2
        self._setup_call_frame(h2)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertNotIn(h2, self.file_subsystem.open_handles)
        self.assertIn(h1, self.file_subsystem.open_handles)
        self.assertIn(h3, self.file_subsystem.open_handles)

        # Reclosing h2 fails
        self._setup_call_frame(h2)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

        # Now close h1 and h3
        self._set_teb_last_error(1234)
        self._setup_call_frame(h1)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self._get_teb_last_error(), 1234)  # Preserved

        self._setup_call_frame(h3)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self._get_teb_last_error(), 1234)  # Preserved


class TestToolhelpHandleDelegation(TestHandleLifecycleBase):
    """Tests CloseHandle delegation to the toolhelp snapshot subsystem."""

    def test_close_single_open_snapshot_success(self) -> None:
        handle = self.toolhelp_subsystem.alloc_snapshot(1)
        esp = self._setup_call_frame(handle)

        success = self._dispatch()
        self.assertTrue(success)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        # Success preserves pre-existing LastError
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)
        self.assertNotIn(handle, self.toolhelp_subsystem.active_snapshots)

    def test_close_snapshot_at_upper_bound(self) -> None:
        handle = self.toolhelp_subsystem.alloc_snapshot(GUEST_TOOLHELP_HANDLE_MAX)
        self.assertEqual(handle, 0x00D10008)
        esp = self._setup_call_frame(handle)

        success = self._dispatch()
        self.assertTrue(success)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)
        self.assertNotIn(handle, self.toolhelp_subsystem.active_snapshots)

    def test_close_snapshot_double_close_fails(self) -> None:
        handle = self.toolhelp_subsystem.alloc_snapshot(3)
        esp = self._setup_call_frame(handle)

        # First close succeeds
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self._get_teb_last_error(), LAST_ERROR_SENTINEL)

        # Second close fails with ERROR_INVALID_HANDLE
        self._setup_call_frame(handle, esp)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_unallocated_snapshot_in_range_fails(self) -> None:
        unallocated_snapshot = GUEST_TOOLHELP_HANDLE_BASE + 7
        esp = self._setup_call_frame(unallocated_snapshot)

        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_multiple_snapshots_interleaved(self) -> None:
        s1 = self.toolhelp_subsystem.alloc_snapshot(1)
        s2 = self.toolhelp_subsystem.alloc_snapshot(2)

        # Close s1
        self._setup_call_frame(s1)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertNotIn(s1, self.toolhelp_subsystem.active_snapshots)
        self.assertIn(s2, self.toolhelp_subsystem.active_snapshots)

        # Close s2
        self._setup_call_frame(s2)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertNotIn(s2, self.toolhelp_subsystem.active_snapshots)


class TestAlienAndNonDelegableHandles(TestHandleLifecycleBase):
    """Tests that non-delegable handles (USER32 objects, Heaps, Sentinels) fail properly."""

    def test_close_user32_cursor_handle_fails(self) -> None:
        cursor_handle = self.user_objects.alloc_object(slot=0, kind="CURSOR")
        self.assertEqual(cursor_handle, 0x00B10001)
        esp = self._setup_call_frame(cursor_handle)

        success = self._dispatch()
        self.assertTrue(success)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)
        # Object must remain intact in USER32 table
        self.assertIn(cursor_handle, self.user_objects.objects)

    def test_close_user32_icon_handle_fails(self) -> None:
        icon_handle = self.user_objects.alloc_object(slot=1, kind="ICON")
        self.assertEqual(icon_handle, 0x00B10002)
        self._setup_call_frame(icon_handle)

        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)
        self.assertIn(icon_handle, self.user_objects.objects)

    def test_close_all_user32_slots_fail(self) -> None:
        for slot in range(GUEST_USER_OBJECT_LIMIT):
            h = GUEST_USER_OBJECT_HANDLE_BASE + slot + 1
            self._setup_call_frame(h)
            self._set_teb_last_error(LAST_ERROR_SENTINEL)
            self.assertTrue(self._dispatch())
            self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
            self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_heap_handles_fail(self) -> None:
        for arena_idx in range(GUEST_HEAP_MAX_HEAPS):
            heap_handle = GUEST_HEAP_BASE + (arena_idx * GUEST_HEAP_ARENA_SIZE)
            self._setup_call_frame(heap_handle)
            self._set_teb_last_error(LAST_ERROR_SENTINEL)
            self.assertTrue(self._dispatch())
            self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
            self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_null_handle_fails(self) -> None:
        self._setup_call_frame(0)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_close_invalid_handle_value_fails(self) -> None:
        self._setup_call_frame(GUEST_INVALID_HANDLE_VALUE)
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_boundary_edge_cases(self) -> None:
        # Base addresses themselves are not valid handles
        edge_handles = [
            GUEST_FILE_HANDLE_BASE,               # 0x00900000 (just below file min)
            GUEST_FILE_HANDLE_LIMIT,              # 0x00900400 (just above file max)
            GUEST_USER_OBJECT_HANDLE_BASE,        # 0x00B10000 (just below user min)
            GUEST_USER_OBJECT_MAX + 1,            # 0x00B10009 (just above user max)
            GUEST_TOOLHELP_HANDLE_BASE,           # 0x00D10000 (just below toolhelp min)
            GUEST_TOOLHELP_HANDLE_MAX_VAL + 1,    # 0x00D10009 (just above toolhelp max)
            0x00123456,                           # arbitrary stack address
            0x00400000,                           # image base
            0xDEADBEEF,                           # arbitrary pointer
        ]
        for h in edge_handles:
            self._setup_call_frame(h)
            self._set_teb_last_error(LAST_ERROR_SENTINEL)
            self.assertTrue(self._dispatch())
            self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0, f"Handle {h:#x} did not return 0")
            self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)


class TestTEBLastErrorAndFaultSemantics(TestHandleLifecycleBase):
    """Tests LastError preservation, overwriting, and memory/state fault semantics."""

    def test_success_preserves_arbitrary_last_error_sentinels(self) -> None:
        sentinels = [0, 1, 2, 5, 80, 183, 0x12345678, 0xFFFFFFFF]
        for sentinel in sentinels:
            h = self.file_subsystem.alloc_handle(1)
            self._set_teb_last_error(sentinel)
            self._setup_call_frame(h)
            self.assertTrue(self._dispatch())
            self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
            self.assertEqual(self._get_teb_last_error(), sentinel)

    def test_failure_overwrites_existing_last_error_with_6(self) -> None:
        self._set_teb_last_error(0xCAFEBABE)
        self._setup_call_frame(0x1234)  # Alien handle
        self.assertTrue(self._dispatch())
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self._get_teb_last_error(), ERROR_INVALID_HANDLE)

    def test_idempotent_error_transitions(self) -> None:
        h1 = self.file_subsystem.alloc_handle(1)
        h2 = self.toolhelp_subsystem.alloc_snapshot(1)

        # 1. Successful file close with sentinel 99
        self._set_teb_last_error(99)
        self._setup_call_frame(h1)
        self.assertTrue(self._dispatch())
        self.assertEqual(self._get_teb_last_error(), 99)

        # 2. Failed alien close: 99 -> 6
        self._setup_call_frame(0x9999)
        self.assertTrue(self._dispatch())
        self.assertEqual(self._get_teb_last_error(), 6)

        # 3. Successful toolhelp close: 6 remains 6 (success does not clear)
        self._setup_call_frame(h2)
        self.assertTrue(self._dispatch())
        self.assertEqual(self._get_teb_last_error(), 6)

    def test_unmapped_stack_frame_causes_memory_fault(self) -> None:
        unmapped_esp = 0x00010000
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, unmapped_esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)

        handled = self._dispatch()
        self.assertFalse(handled)
        self.assertEqual(self.state.get("status"), "GUEST_STOP_MEMORY")
        self.assertEqual(self.state.get("target"), unmapped_esp)

    def test_stack_overflow_wrap_causes_memory_fault(self) -> None:
        wrapping_esp = 0xFFFFFFFC
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, wrapping_esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)

        handled = self._dispatch()
        self.assertFalse(handled)
        self.assertEqual(self.state.get("status"), "GUEST_STOP_MEMORY")

    def test_null_teb_on_error_causes_api_state_fault(self) -> None:
        self.state["tls_current_teb"] = 0
        self._setup_call_frame(0xDEAD)  # Alien handle trigger failure write

        handled = self._dispatch()
        self.assertFalse(handled)
        self.assertEqual(self.state.get("status"), "GUEST_STOP_API_STATE")
        self.assertEqual(self.state.get("target"), 0)

    def test_unmapped_teb_causes_memory_fault(self) -> None:
        unmapped_teb = 0x00200000
        self.state["tls_current_teb"] = unmapped_teb
        self._setup_call_frame(0xDEAD)

        handled = self._dispatch()
        self.assertFalse(handled)
        self.assertEqual(self.state.get("status"), "GUEST_STOP_MEMORY")
        self.assertEqual(self.state.get("target"), unmapped_teb + LAST_ERROR_OFFSET)

    def test_teb_address_overflow_causes_memory_fault(self) -> None:
        overflowing_teb = 0xFFFFFFE0
        self.state["tls_current_teb"] = overflowing_teb
        self._setup_call_frame(0xDEAD)

        handled = self._dispatch()
        self.assertFalse(handled)
        self.assertEqual(self.state.get("status"), "GUEST_STOP_MEMORY")
        self.assertEqual(self.state.get("target"), 0xFFFFFFFF)


class TestRegisterPreservation(TestHandleLifecycleBase):
    """Verifies that non-result registers and flags are bit-for-bit preserved."""

    def test_registers_preserved_on_success(self) -> None:
        h = self.file_subsystem.alloc_handle(1)
        esp = self._setup_call_frame(h)
        regs_before = self._snapshot_registers()

        self.assertTrue(self._dispatch())

        regs_after = self._snapshot_registers()
        # Only EAX (return value), ESP (+8), EIP (return_ip) should differ
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EAX], 1)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_ESP], esp + 8)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EIP], RETURN_ADDRESS)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EFLAGS], regs_before[x86_const.UC_X86_REG_EFLAGS])

        for reg in OTHER_REGISTERS:
            self.assertEqual(
                regs_after[reg], regs_before[reg],
                f"Register {reg} clobbered on success: {regs_after[reg]:#x} != {regs_before[reg]:#x}"
            )

    def test_registers_preserved_on_failure(self) -> None:
        esp = self._setup_call_frame(0xCAFE)  # Alien handle
        regs_before = self._snapshot_registers()

        self.assertTrue(self._dispatch())

        regs_after = self._snapshot_registers()
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EAX], 0)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_ESP], esp + 8)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EIP], RETURN_ADDRESS)
        self.assertEqual(regs_after[x86_const.UC_X86_REG_EFLAGS], regs_before[x86_const.UC_X86_REG_EFLAGS])

        for reg in OTHER_REGISTERS:
            self.assertEqual(
                regs_after[reg], regs_before[reg],
                f"Register {reg} clobbered on failure: {regs_after[reg]:#x} != {regs_before[reg]:#x}"
            )


if __name__ == "__main__":
    unittest.main()
