#!/usr/bin/env python3
"""Synthetic-memory tests for the GetCursorPos oracle."""
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

from cursor_oracle import _cursor_query_import


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
TEB_BASE = 0x00C00000
POINT_BASE = 0x00700000
LAST_ERROR_OFFSET = 0x34
ERROR_NOACCESS = 998
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000003
IMPORT_INDEX = 3
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


class CursorOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(POINT_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (POINT_BASE, POINT_BASE + PAGE_SIZE),
        ]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "tls_current_teb": TEB_BASE,
            "cursor_coords": (640, 480),
        }
        self.row = {
            "library": "USER32.dll",
            "name": "GetCursorPos",
            "index": IMPORT_INDEX,
        }

    def _setup_cpu(self, esp: int) -> dict[int, int]:
        values = {
            x86_const.UC_X86_REG_EAX: EAX_SENTINEL,
            x86_const.UC_X86_REG_EIP: IMPORT_IP,
            x86_const.UC_X86_REG_ESP: esp,
            x86_const.UC_X86_REG_EFLAGS: FLAGS_SENTINEL,
            x86_const.UC_X86_REG_EBX: 0x11111111,
            x86_const.UC_X86_REG_ECX: 0x22222222,
            x86_const.UC_X86_REG_EDX: 0x33333333,
            x86_const.UC_X86_REG_ESI: 0x44444444,
            x86_const.UC_X86_REG_EDI: 0x55555555,
            x86_const.UC_X86_REG_EBP: 0x66666666,
        }
        for register, value in values.items():
            self.engine.reg_write(register, value)
        return values

    def _map_teb(self, initial_error: int = LAST_ERROR_SENTINEL) -> None:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((TEB_BASE, TEB_BASE + PAGE_SIZE))
        self.engine.mem_write(
            TEB_BASE + LAST_ERROR_OFFSET, struct.pack("<I", initial_error))

    def test_valid_pointer_writes_coordinates(self) -> None:
        esp = STACK_BASE + 0x100
        pt_addr = POINT_BASE + 0x20
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, pt_addr))
        self.engine.mem_write(pt_addr, b"\xaa" * 8)
        initial = self._setup_cpu(esp)

        handled = _cursor_query_import(
            self.engine, x86_const, unicorn, self.row, self.mapped_ranges,
            self.state)

        self.assertTrue(handled)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)

        # Non-scratch registers preserved
        for reg in OTHER_REGISTERS:
            self.assertEqual(
                self.engine.reg_read(reg), initial[reg])

        # Verify coordinates written
        written = self.engine.mem_read(pt_addr, 8)
        x, y = struct.unpack("<ii", written)
        self.assertEqual((x, y), (640, 480))

    def test_null_pointer_sets_error_noaccess(self) -> None:
        esp = STACK_BASE + 0x100
        self._map_teb()
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, 0))
        initial = self._setup_cpu(esp)

        handled = _cursor_query_import(
            self.engine, x86_const, unicorn, self.row, self.mapped_ranges,
            self.state)

        self.assertTrue(handled)
        self.assertTrue(self.state["resume"])
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 8)

        # Verify LastError
        raw_error = self.engine.mem_read(TEB_BASE + LAST_ERROR_OFFSET, 4)
        error, = struct.unpack("<I", raw_error)
        self.assertEqual(error, ERROR_NOACCESS)

    def test_unmapped_point_causes_memory_fault(self) -> None:
        esp = STACK_BASE + 0x100
        unmapped_pt = 0x00800000
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, unmapped_pt))
        self._setup_cpu(esp)

        handled = _cursor_query_import(
            self.engine, x86_const, unicorn, self.row, self.mapped_ranges,
            self.state)

        self.assertFalse(handled)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], unmapped_pt)

    def test_readonly_point_causes_memory_fault(self) -> None:
        esp = STACK_BASE + 0x100
        ro_page = 0x00900000
        self.engine.mem_map(ro_page, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((ro_page, ro_page + PAGE_SIZE))
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, ro_page))
        self._setup_cpu(esp)

        handled = _cursor_query_import(
            self.engine, x86_const, unicorn, self.row, self.mapped_ranges,
            self.state)

        self.assertFalse(handled)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], ro_page)

    def test_unmapped_stack_causes_memory_fault(self) -> None:
        unmapped_esp = 0x00800000
        self._setup_cpu(unmapped_esp)

        handled = _cursor_query_import(
            self.engine, x86_const, unicorn, self.row, self.mapped_ranges,
            self.state)

        self.assertFalse(handled)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], unmapped_esp)

    def test_wrong_library_or_name_ignored(self) -> None:
        esp = STACK_BASE + 0x100
        self.engine.mem_write(esp, struct.pack("<II", RETURN_ADDRESS, POINT_BASE))
        self._setup_cpu(esp)

        wrong_lib = {"library": "KERNEL32.dll", "name": "GetCursorPos", "index": 0}
        self.assertFalse(_cursor_query_import(
            self.engine, x86_const, unicorn, wrong_lib, self.mapped_ranges, self.state))

        wrong_name = {"library": "USER32.dll", "name": "SetCursorPos", "index": 0}
        self.assertFalse(_cursor_query_import(
            self.engine, x86_const, unicorn, wrong_name, self.mapped_ranges, self.state))


if __name__ == "__main__":
    unittest.main()
