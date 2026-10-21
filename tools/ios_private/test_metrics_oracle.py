#!/usr/bin/env python3
"""Synthetic-memory tests for the bounded GetSystemMetrics oracle."""
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

from metrics_oracle import apply_metrics


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
LAST_ERROR_SENTINEL = 0x76543210
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000023
IMPORT_INDEX = 35
SM_SWAPBUTTON = 23
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD7
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


class MetricsOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "tls_current_teb": 0,
        }
        self.row = {
            "library": "USER32.dll",
            "name": "GetSystemMetrics",
            "index": IMPORT_INDEX,
        }
        self.write_frame(SM_SWAPBUTTON)

    def write_frame(self, metric: int, *, esp: int = STACK_BASE,
                    return_address: int = RETURN_ADDRESS) -> bytes:
        frame = struct.pack("<II", return_address, metric & 0xFFFFFFFF)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)
        return frame

    def set_registers(self, esp: int) -> None:
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.engine.reg_write(register, 0x11110000 + offset)

    def map_teb(self) -> int:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((TEB_BASE, TEB_BASE + PAGE_SIZE))
        address = TEB_BASE + LAST_ERROR_OFFSET
        self.engine.mem_write(address, struct.pack("<I", LAST_ERROR_SENTINEL))
        return address

    def call_import(self, *, row: dict[str, object] | None = None) -> bool:
        return apply_metrics(
            self.engine, x86_const, unicorn, row or self.row,
            self.mapped_ranges, self.state)

    def register_snapshot(self) -> dict[int, int]:
        return {register: self.engine.reg_read(register)
                for register in SNAPSHOT_REGISTERS}

    def assert_completed_call(self, *, esp: int = STACK_BASE,
                              return_address: int = RETURN_ADDRESS) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         return_address)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         (esp + 8) & 0xFFFFFFFF)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         FLAGS_SENTINEL)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])

    def assert_memory_fault_atomic(self, *, esp: int, address: int,
                                   mapped_ranges: list[tuple[int, int]] | None = None,
                                   protect: int | None = None,
                                   frame_size: int | None = 8) -> None:
        if esp == STACK_BASE:
            self.write_frame(SM_SWAPBUTTON, esp=esp)
        else:
            self.set_registers(esp)
        frame_before = (bytes(self.engine.mem_read(esp, frame_size))
                        if frame_size is not None else None)
        if protect is not None:
            self.engine.mem_protect(STACK_BASE, PAGE_SIZE, protect)
        if mapped_ranges is not None:
            self.mapped_ranges = mapped_ranges
        registers_before = self.register_snapshot()
        state_before = dict(self.state)

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        if frame_size is not None:
            self.assertEqual(bytes(self.engine.mem_read(esp, frame_size)),
                             frame_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], address & 0xFFFFFFFF)
        self.assertEqual(self.state["memory_fault"], {
            "access": "read", "address": address, "size": 8,
        })
        self.assertEqual(self.state["api_calls"], state_before["api_calls"])
        self.assertFalse(self.state["resume"])

    def test_swapbutton_zero_returns_success_without_touching_last_error(self) -> None:
        last_error_address = self.map_teb()
        frame = self.write_frame(SM_SWAPBUTTON)
        stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
        last_error_before = bytes(self.engine.mem_read(last_error_address, 4))

        self.assertTrue(self.call_import())

        self.assert_completed_call()
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                         stack_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame)
        self.assertEqual(bytes(self.engine.mem_read(last_error_address, 4)),
                         last_error_before)
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["library"], "USER32.dll")
        self.assertEqual(api["name"], "GetSystemMetrics")
        self.assertEqual(api["import_index"], IMPORT_INDEX)
        self.assertEqual(api["tag"], 0xF0000000 + IMPORT_INDEX)
        self.assertEqual(api["call_ip"], IMPORT_IP)
        self.assertEqual(api["esp_before"], STACK_BASE)
        self.assertEqual(api["argument_count"], 1)
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [SM_SWAPBUTTON])
        self.assertEqual(api["result"], 0)
        self.assertEqual(api["profile"], "primary_button_left")
        self.assertEqual(api["esp_after"], STACK_BASE + 8)

    def test_readonly_frame_aliased_with_last_error_is_read_only_input(self) -> None:
        esp = STACK_BASE + 0x100
        return_address = 0x76543210
        frame = self.write_frame(SM_SWAPBUTTON, esp=esp,
                                 return_address=return_address)
        self.state["tls_current_teb"] = esp - LAST_ERROR_OFFSET
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        frame_before = bytes(self.engine.mem_read(esp, 8))
        registers_before = self.register_snapshot()

        self.assertTrue(self.call_import())

        self.assert_completed_call(esp=esp, return_address=return_address)
        self.assertEqual(bytes(self.engine.mem_read(esp, 8)), frame_before)
        self.assertEqual(bytes(self.engine.mem_read(esp, 8)), frame)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         registers_before[x86_const.UC_X86_REG_EFLAGS])
        self.assertEqual(self.state["api_calls"][0]["return_address"],
                         return_address)

    def test_metrics_zero_one_and_uint32_max_are_unsupported_unchanged(self) -> None:
        for metric in (0, 1, 0xFFFFFFFF):
            with self.subTest(metric=metric):
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                frame = self.write_frame(metric)
                registers_before = self.register_snapshot()
                memory_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                state_before = dict(self.state)

                self.assertFalse(self.call_import())

                self.assertEqual(self.register_snapshot(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 memory_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame)
                self.assertEqual(self.state, state_before)
                self.assertEqual(self.state["api_calls"], [])
                self.assertFalse(self.state["resume"])

    def test_wrong_library_or_export_is_unsupported_without_side_effects(self) -> None:
        rows = (
            {"library": "KERNEL32.dll", "name": "GetSystemMetrics",
             "index": IMPORT_INDEX},
            {"library": "USER32.dll", "name": "GetSystemMetricsA",
             "index": IMPORT_INDEX},
        )
        for row in rows:
            with self.subTest(row=row):
                registers_before = self.register_snapshot()
                frame_before = bytes(self.engine.mem_read(STACK_BASE, 8))
                state_before = dict(self.state)

                self.assertFalse(self.call_import(row=row))

                self.assertEqual(self.register_snapshot(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)),
                                 frame_before)
                self.assertEqual(self.state, state_before)

    def test_unmapped_partial_and_nonreadable_frames_fault_atomically(self) -> None:
        self.assert_memory_fault_atomic(
            esp=0x00600000, address=0x00600000, frame_size=None)

        self.assert_memory_fault_atomic(
            esp=STACK_BASE, address=STACK_BASE,
            mapped_ranges=[(STACK_BASE, STACK_BASE + 4)])

        self.assert_memory_fault_atomic(
            esp=STACK_BASE, address=STACK_BASE,
            protect=unicorn.UC_PROT_WRITE)

    def test_frame_extent_overflow_faults_at_frame_base(self) -> None:
        high_page = 0xFFFFF000
        self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_write(0xFFFFFFFC, struct.pack("<I", RETURN_ADDRESS))
        self.mapped_ranges.append((high_page, 0x100000000))
        self.assert_memory_fault_atomic(
            esp=0xFFFFFFFC, address=0xFFFFFFFC, frame_size=4)


if __name__ == "__main__":
    unittest.main()
