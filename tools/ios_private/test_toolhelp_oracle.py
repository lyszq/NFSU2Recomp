#!/usr/bin/env python3
"""Synthetic-memory unit tests for the Win32 Toolhelp32 snapshot oracle."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(__file__).resolve().parent
for path in (ROOT / "tools", PRIVATE, ROOT / "out" / "private-deps"):
    if path.is_dir():
        sys.path.insert(0, str(path))

import unicorn
from unicorn import x86_const

from toolhelp_oracle import (
    TOOLHELP_IMPORT_LIBRARY,
    SNAPSHOT_IMPORT_NAME,
    PROCESS_FIRST_IMPORT_NAME,
    PROCESS_NEXT_IMPORT_NAME,
    CLOSE_HANDLE_IMPORT_NAME,
    TOOLHELP_PROFILE,
    TH32CS_SNAPPROCESS,
    TH32CS_INHERIT,
    ALLOWED_SNAPSHOT_FLAGS,
    SNAPSHOT_HANDLE_BASE,
    SNAPSHOT_HANDLE_MIN,
    SNAPSHOT_HANDLE_MAX,
    MAX_SNAPSHOTS,
    INVALID_HANDLE_VALUE,
    PROCESSENTRY32_SIZE,
    DEFAULT_PROCESS_ID,
    DEFAULT_THREAD_COUNT,
    DEFAULT_PRIORITY_CLASS,
    DEFAULT_EXE_NAME,
    ERROR_INVALID_HANDLE,
    ERROR_NO_MORE_FILES,
    ERROR_INVALID_PARAMETER,
    ERROR_INSUFFICIENT_BUFFER,
    TEB_BASE,
    LAST_ERROR_OFFSET,
    create_toolhelp32_snapshot,
    process32_first,
    process32_next,
    toolhelp_close_handle,
    toolhelp_import,
    CreateToolhelp32Snapshot,
    Process32First,
    Process32Next,
)


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
BUFFER_BASE = 0x00700000
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000020
IMPORT_INDEX = 32

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


class ToolhelpOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(BUFFER_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + PAGE_SIZE),
            (BUFFER_BASE, BUFFER_BASE + PAGE_SIZE),
        ]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "tls_current_teb": TEB_BASE,
            "snapshots": {},
        }
        self.engine.mem_write(
            TEB_BASE + LAST_ERROR_OFFSET,
            struct.pack("<I", LAST_ERROR_SENTINEL))
        self.set_registers(STACK_BASE + 0x100)

    def set_registers(self, esp: int) -> None:
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.engine.reg_write(register, 0x11110000 + offset)

    def register_snapshot(self) -> dict[int, int]:
        return {reg: self.engine.reg_read(reg) for reg in SNAPSHOT_REGISTERS}

    def assert_other_registers_preserved(
            self, before: dict[int, int]) -> None:
        for reg in OTHER_REGISTERS:
            self.assertEqual(
                self.engine.reg_read(reg), before[reg],
                f"Register {reg} was clobbered")

    def read_last_error(self) -> int:
        data = self.engine.mem_read(TEB_BASE + LAST_ERROR_OFFSET, 4)
        return struct.unpack("<I", data)[0]

    def write_snapshot_frame(self, dw_flags: int, th32_process_id: int,
                             esp: int = STACK_BASE + 0x100,
                             return_address: int = RETURN_ADDRESS) -> None:
        frame = struct.pack("<III", return_address, dw_flags, th32_process_id)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)

    def write_process32_frame(self, h_snapshot: int, lppe: int,
                              esp: int = STACK_BASE + 0x100,
                              return_address: int = RETURN_ADDRESS) -> None:
        frame = struct.pack("<III", return_address, h_snapshot, lppe)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)

    def write_close_handle_frame(self, handle: int,
                                 esp: int = STACK_BASE + 0x100,
                                 return_address: int = RETURN_ADDRESS) -> None:
        frame = struct.pack("<II", return_address, handle)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)

    def test_successful_toolhelp_lifecycle(self) -> None:
        """Requirement 1: CreateToolhelp32Snapshot + Process32First + Process32Next + CloseHandle."""
        esp_init = STACK_BASE + 0x100
        row_snap = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
        regs_before = self.register_snapshot()

        # 1. CreateToolhelp32Snapshot
        self.assertTrue(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))

        self.assertTrue(self.state["resume"])
        snapshot_handle = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        self.assertEqual(snapshot_handle, SNAPSHOT_HANDLE_MIN)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assert_other_registers_preserved(regs_before)
        self.assertIn(snapshot_handle, self.state["snapshots"])
        self.assertEqual(self.state["snapshots"][snapshot_handle]["iter_index"], 0)
        self.assertEqual(self.state["snapshots"][snapshot_handle]["process_id"], DEFAULT_PROCESS_ID)

        # 2. Process32First
        # Initialize dwSize in PROCESSENTRY32 structure
        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", PROCESSENTRY32_SIZE))
        row_first = {"library": "kernel32.dll", "name": "Process32First", "index": 2}
        self.write_process32_frame(snapshot_handle, BUFFER_BASE, esp=esp_init)
        regs_before = self.register_snapshot()

        self.assertTrue(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assert_other_registers_preserved(regs_before)
        self.assertEqual(self.state["snapshots"][snapshot_handle]["iter_index"], 1)

        # Validate PROCESSENTRY32 struct layout (296 bytes)
        entry_raw = bytes(self.engine.mem_read(BUFFER_BASE, PROCESSENTRY32_SIZE))
        (
            dw_size, cnt_usage, th32_process_id, th32_default_heap_id,
            th32_module_id, cnt_threads, th32_parent_process_id,
            pc_pri_class_base, dw_flags, sz_exe_file
        ) = struct.unpack("<IIIIIIIiI260s", entry_raw)

        self.assertEqual(dw_size, PROCESSENTRY32_SIZE)
        self.assertEqual(cnt_usage, 0)
        self.assertEqual(th32_process_id, DEFAULT_PROCESS_ID)
        self.assertEqual(th32_default_heap_id, 0)
        self.assertEqual(th32_module_id, 0)
        self.assertEqual(cnt_threads, DEFAULT_THREAD_COUNT)
        self.assertEqual(th32_parent_process_id, 0)
        self.assertEqual(pc_pri_class_base, DEFAULT_PRIORITY_CLASS)
        self.assertEqual(dw_flags, 0)
        self.assertEqual(sz_exe_file.split(b"\0", 1)[0], b"SPEED2.EXE")

        # 3. Process32Next -> ERROR_NO_MORE_FILES
        row_next = {"library": "kernel32.dll", "name": "Process32Next", "index": 3}
        self.write_process32_frame(snapshot_handle, BUFFER_BASE, esp=esp_init)
        regs_before = self.register_snapshot()

        self.assertTrue(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assertEqual(self.read_last_error(), ERROR_NO_MORE_FILES)
        self.assert_other_registers_preserved(regs_before)

        # 4. CloseHandle
        row_close = {"library": "kernel32.dll", "name": "CloseHandle", "index": 4}
        self.write_close_handle_frame(snapshot_handle, esp=esp_init)
        regs_before = self.register_snapshot()

        self.assertTrue(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row_close, self.mapped_ranges, self.state))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 8)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assert_other_registers_preserved(regs_before)
        self.assertNotIn(snapshot_handle, self.state["snapshots"])

    def test_snapshot_inherit_flag_accepted(self) -> None:
        """CreateToolhelp32Snapshot accepts TH32CS_SNAPPROCESS | TH32CS_INHERIT."""
        esp_init = STACK_BASE + 0x100
        row = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}
        self.write_snapshot_frame(TH32CS_SNAPPROCESS | TH32CS_INHERIT, 1234, esp=esp_init)

        self.assertTrue(CreateToolhelp32Snapshot(
            self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))

        handle = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        self.assertEqual(handle, SNAPSHOT_HANDLE_MIN)
        self.assertEqual(self.state["snapshots"][handle]["process_id"], 1234)

    def test_invalid_flags_in_create_snapshot(self) -> None:
        """Requirement 2: Invalid flags passed to CreateToolhelp32Snapshot."""
        row = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}
        invalid_flags = (0, 1, 4, 8, 16, 0x12345678, TH32CS_INHERIT)

        for flags in invalid_flags:
            with self.subTest(flags=flags):
                esp_init = STACK_BASE + 0x100
                self.write_snapshot_frame(flags, 0, esp=esp_init)
                regs_before = self.register_snapshot()

                self.assertTrue(create_toolhelp32_snapshot(
                    self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))

                self.assertEqual(
                    self.engine.reg_read(x86_const.UC_X86_REG_EAX), INVALID_HANDLE_VALUE)
                self.assertEqual(
                    self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
                self.assertEqual(
                    self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
                self.assertEqual(self.read_last_error(), ERROR_INVALID_PARAMETER)
                self.assert_other_registers_preserved(regs_before)
                self.assertEqual(len(self.state["snapshots"]), 0)

    def test_process32_first_invalid_handle(self) -> None:
        """Requirement 3: Process32First with invalid handle."""
        esp_init = STACK_BASE + 0x100
        row = {"library": "kernel32.dll", "name": "Process32First", "index": 1}
        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", PROCESSENTRY32_SIZE))

        for invalid_handle in (0, 0x00D10001, 0x00D10009, 0xDEADBEEF):
            with self.subTest(handle=invalid_handle):
                self.write_process32_frame(invalid_handle, BUFFER_BASE, esp=esp_init)
                regs_before = self.register_snapshot()

                self.assertTrue(Process32First(
                    self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))

                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
                self.assertEqual(self.read_last_error(), ERROR_INVALID_HANDLE)
                self.assert_other_registers_preserved(regs_before)

    def test_process32_first_dwsize_less_than_296(self) -> None:
        """Requirement 4: Process32First with dwSize < 296."""
        # Setup valid snapshot
        self.state["snapshots"][SNAPSHOT_HANDLE_MIN] = {"iter_index": 0, "process_id": 100}
        row = {"library": "kernel32.dll", "name": "Process32First", "index": 1}
        esp_init = STACK_BASE + 0x100

        for bad_size in (0, 4, 100, 200, 295):
            with self.subTest(bad_size=bad_size):
                self.engine.mem_write(BUFFER_BASE, struct.pack("<I", bad_size))
                self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)
                regs_before = self.register_snapshot()

                self.assertTrue(process32_first(
                    self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))

                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 12)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
                self.assertEqual(self.read_last_error(), ERROR_INSUFFICIENT_BUFFER)
                self.assert_other_registers_preserved(regs_before)
                self.assertEqual(self.state["snapshots"][SNAPSHOT_HANDLE_MIN]["iter_index"], 0)

    def test_process32_first_dwsize_greater_than_296(self) -> None:
        """Process32First succeeds with dwSize >= 296."""
        self.state["snapshots"][SNAPSHOT_HANDLE_MIN] = {"iter_index": 0, "process_id": 100}
        row = {"library": "kernel32.dll", "name": "Process32First", "index": 1}
        esp_init = STACK_BASE + 0x100

        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", 512))
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)

        self.assertTrue(process32_first(
            self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.state["snapshots"][SNAPSHOT_HANDLE_MIN]["iter_index"], 1)

    def test_process32_next_no_more_files_and_rewind(self) -> None:
        """Requirement 5: Process32Next returning ERROR_NO_MORE_FILES and rewind."""
        self.state["snapshots"][SNAPSHOT_HANDLE_MIN] = {"iter_index": 0, "process_id": 100}
        esp_init = STACK_BASE + 0x100
        row_first = {"library": "kernel32.dll", "name": "Process32First", "index": 1}
        row_next = {"library": "kernel32.dll", "name": "Process32Next", "index": 2}

        # First call Process32First
        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", PROCESSENTRY32_SIZE))
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)
        self.assertTrue(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)

        # Next call Process32Next -> ERROR_NO_MORE_FILES
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)
        self.assertTrue(Process32Next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.read_last_error(), ERROR_NO_MORE_FILES)

        # Subsequent call Process32Next -> still ERROR_NO_MORE_FILES
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)
        self.assertTrue(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.read_last_error(), ERROR_NO_MORE_FILES)

        # Calling Process32First again rewinds the snapshot
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, BUFFER_BASE, esp=esp_init)
        self.assertTrue(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.state["snapshots"][SNAPSHOT_HANDLE_MIN]["iter_index"], 1)

    def test_process32_next_errors(self) -> None:
        """Process32Next error validation: invalid handle and dwSize < 296."""
        esp_init = STACK_BASE + 0x100
        row_next = {"library": "kernel32.dll", "name": "Process32Next", "index": 2}

        # Invalid handle
        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", PROCESSENTRY32_SIZE))
        self.write_process32_frame(0x00D10001, BUFFER_BASE, esp=esp_init)
        self.assertTrue(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.read_last_error(), ERROR_INVALID_HANDLE)

        # Valid handle, but buffer dwSize < 296
        self.state["snapshots"][0x00D10001] = {"iter_index": 0, "process_id": 100}
        self.engine.mem_write(BUFFER_BASE, struct.pack("<I", 100))
        self.write_process32_frame(0x00D10001, BUFFER_BASE, esp=esp_init)
        self.assertTrue(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.read_last_error(), ERROR_INSUFFICIENT_BUFFER)

    def test_double_close_handle_and_unhandled_handles(self) -> None:
        """Requirement 6: Double CloseHandle and handle range dispatch."""
        esp_init = STACK_BASE + 0x100
        row = {"library": "kernel32.dll", "name": "CloseHandle", "index": 1}
        handle = SNAPSHOT_HANDLE_MIN
        self.state["snapshots"][handle] = {"iter_index": 0, "process_id": 100}

        # First close succeeds
        self.write_close_handle_frame(handle, esp=esp_init)
        regs_before = self.register_snapshot()
        self.assertTrue(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 8)
        self.assertNotIn(handle, self.state["snapshots"])
        self.assert_other_registers_preserved(regs_before)

        # Second close fails with ERROR_INVALID_HANDLE
        self.write_close_handle_frame(handle, esp=esp_init)
        regs_before = self.register_snapshot()
        self.assertTrue(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp_init + 8)
        self.assertEqual(self.read_last_error(), ERROR_INVALID_HANDLE)
        self.assert_other_registers_preserved(regs_before)

        # Handle out of snapshot range returns False without side effects
        for unhandled in (0, 0x00D10000, 0x00D10009, 0x00500000, 0xFFFFFFFF):
            with self.subTest(unhandled=unhandled):
                self.write_close_handle_frame(unhandled, esp=esp_init)
                regs_before = self.register_snapshot()
                self.assertFalse(toolhelp_close_handle(
                    self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))
                self.assertEqual(self.register_snapshot(), regs_before)

    def test_exhaustion_of_8_snapshots_and_slot_recycling(self) -> None:
        """Requirement 7: Exhaustion of 8 snapshot handles and recycling."""
        row_snap = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}
        row_close = {"library": "kernel32.dll", "name": "CloseHandle", "index": 2}
        esp_init = STACK_BASE + 0x100
        allocated = []

        # Allocate 8 snapshots
        for i in range(MAX_SNAPSHOTS):
            self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
            self.assertTrue(create_toolhelp32_snapshot(
                self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
            handle = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
            expected = SNAPSHOT_HANDLE_BASE + 1 + i
            self.assertEqual(handle, expected)
            allocated.append(handle)

        self.assertEqual(len(self.state["snapshots"]), MAX_SNAPSHOTS)

        # 9th attempt fails with ERROR_INSUFFICIENT_BUFFER
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
        self.assertTrue(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), INVALID_HANDLE_VALUE)
        self.assertEqual(self.read_last_error(), ERROR_INSUFFICIENT_BUFFER)

        # Close handle 3 and handle 6
        target_a = allocated[2]  # 0x00D10003
        target_b = allocated[5]  # 0x00D10006
        self.write_close_handle_frame(target_a, esp=esp_init)
        self.assertTrue(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row_close, self.mapped_ranges, self.state))
        self.write_close_handle_frame(target_b, esp=esp_init)
        self.assertTrue(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row_close, self.mapped_ranges, self.state))

        # Reallocation grabs the lowest available slot: target_a
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
        self.assertTrue(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), target_a)

        # Reallocation grabs next available slot: target_b
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
        self.assertTrue(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), target_b)

        # Now full again
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)
        self.assertTrue(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), INVALID_HANDLE_VALUE)
        self.assertEqual(self.read_last_error(), ERROR_INSUFFICIENT_BUFFER)

    def test_unmapped_memory_stack_faults(self) -> None:
        """Requirement 8: Unmapped memory faults handling for stack."""
        unmapped_esp = 0x00100000  # Not in mapped_ranges
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, unmapped_esp)
        row_snap = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}
        row_first = {"library": "kernel32.dll", "name": "Process32First", "index": 2}
        row_next = {"library": "kernel32.dll", "name": "Process32Next", "index": 3}
        row_close = {"library": "kernel32.dll", "name": "CloseHandle", "index": 4}

        regs_before = self.register_snapshot()

        # CreateToolhelp32Snapshot stack fault
        self.assertFalse(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")
        self.assertEqual(self.state["memory_fault"]["address"], unmapped_esp)
        self.assertEqual(self.state["memory_fault"]["size"], 12)
        self.assertEqual(self.register_snapshot(), regs_before)

        # Process32First stack fault
        self.state["status"] = None
        self.assertFalse(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")
        self.assertEqual(self.state["memory_fault"]["address"], unmapped_esp)

        # Process32Next stack fault
        self.state["status"] = None
        self.assertFalse(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")

        # CloseHandle stack fault
        self.state["status"] = None
        self.assertFalse(toolhelp_close_handle(
            self.engine, x86_const, unicorn, row_close, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")
        self.assertEqual(self.state["memory_fault"]["size"], 8)

    def test_unmapped_memory_lppe_buffer_faults(self) -> None:
        """Requirement 8: Unmapped and read-only memory faults for lppe."""
        self.state["snapshots"][SNAPSHOT_HANDLE_MIN] = {"iter_index": 0, "process_id": 100}
        esp_init = STACK_BASE + 0x100
        row_first = {"library": "kernel32.dll", "name": "Process32First", "index": 1}
        row_next = {"library": "kernel32.dll", "name": "Process32Next", "index": 2}
        unmapped_lppe = 0x00800000

        # Unmapped read of dwSize in Process32First
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, unmapped_lppe, esp=esp_init)
        regs_before = self.register_snapshot()
        self.assertFalse(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")
        self.assertEqual(self.state["memory_fault"]["address"], unmapped_lppe)
        self.assertEqual(self.state["memory_fault"]["size"], 4)
        self.assertEqual(self.register_snapshot(), regs_before)

        # Unmapped read of dwSize in Process32Next
        self.state["status"] = None
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, unmapped_lppe, esp=esp_init)
        self.assertFalse(process32_next(
            self.engine, x86_const, unicorn, row_next, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "read")

        # Read-only buffer in Process32First: dwSize read succeeds, write of 296 bytes faults
        ro_page = 0x00900000
        self.engine.mem_map(ro_page, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((ro_page, ro_page + PAGE_SIZE))
        self.engine.mem_write(ro_page, struct.pack("<I", PROCESSENTRY32_SIZE))

        self.state["status"] = None
        self.write_process32_frame(SNAPSHOT_HANDLE_MIN, ro_page, esp=esp_init)
        regs_before = self.register_snapshot()
        self.assertFalse(process32_first(
            self.engine, x86_const, unicorn, row_first, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "write")
        self.assertEqual(self.state["memory_fault"]["address"], ro_page)
        self.assertEqual(self.state["memory_fault"]["size"], PROCESSENTRY32_SIZE)
        self.assertEqual(self.register_snapshot(), regs_before)
        # Verify iter_index did not advance
        self.assertEqual(self.state["snapshots"][SNAPSHOT_HANDLE_MIN]["iter_index"], 0)

    def test_teb_memory_and_state_faults(self) -> None:
        """Requirement 8: TEB unmapped, read-only, and invalid state faults."""
        esp_init = STACK_BASE + 0x100
        row_snap = {"library": "kernel32.dll", "name": "CreateToolhelp32Snapshot", "index": 1}

        # 1. Zero TEB triggers api state fault
        self.state["tls_current_teb"] = 0
        self.write_snapshot_frame(0, 0, esp=esp_init)  # Invalid flags forces error write
        regs_before = self.register_snapshot()
        self.assertFalse(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["api_state_fault"]["reason"], "current_teb_invalid")
        self.assertEqual(self.register_snapshot(), regs_before)

        # 2. Unmapped TEB forces memory fault
        self.state["tls_current_teb"] = 0x00300000  # Unmapped
        self.state["status"] = None
        self.assertFalse(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "write")
        self.assertEqual(self.state["memory_fault"]["address"], 0x00300000 + LAST_ERROR_OFFSET)
        self.assertEqual(self.state["memory_fault"]["size"], 4)

        # 3. Read-only TEB forces memory fault
        ro_teb = 0x00400000
        self.engine.mem_map(ro_teb, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((ro_teb, ro_teb + PAGE_SIZE))
        self.state["tls_current_teb"] = ro_teb
        self.state["status"] = None
        self.assertFalse(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["access"], "write")
        self.assertEqual(self.state["memory_fault"]["address"], ro_teb + LAST_ERROR_OFFSET)

        # 4. TEB address addition overflow faults at 0xFFFFFFFF
        self.state["tls_current_teb"] = 0xFFFFFFE0
        self.state["status"] = None
        self.assertFalse(create_toolhelp32_snapshot(
            self.engine, x86_const, unicorn, row_snap, self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["memory_fault"]["address"], 0xFFFFFFFF)

    def test_toolhelp_import_dispatcher(self) -> None:
        """Test unified toolhelp_import dispatcher."""
        esp_init = STACK_BASE + 0x100
        self.write_snapshot_frame(TH32CS_SNAPPROCESS, 0, esp=esp_init)

        # Dispatch CreateToolhelp32Snapshot
        row = {"library": "KERNEL32.DLL", "name": "CreateToolhelp32Snapshot", "index": 5}
        self.assertTrue(toolhelp_import(
            self.engine, x86_const, unicorn, row, self.mapped_ranges, self.state))
        handle = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        self.assertEqual(handle, SNAPSHOT_HANDLE_MIN)

        # Wrong library name
        wrong_lib_row = {"library": "user32.dll", "name": "CreateToolhelp32Snapshot", "index": 5}
        self.assertFalse(toolhelp_import(
            self.engine, x86_const, unicorn, wrong_lib_row, self.mapped_ranges, self.state))

        # Unknown export name
        wrong_name_row = {"library": "kernel32.dll", "name": "NonExistentAPI", "index": 5}
        self.assertFalse(toolhelp_import(
            self.engine, x86_const, unicorn, wrong_name_row, self.mapped_ranges, self.state))


if __name__ == "__main__":
    unittest.main()
