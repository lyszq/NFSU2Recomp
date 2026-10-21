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

from cursor_oracle import CURSOR_PROFILE, _cursor_query_import


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
FLAGS_SENTINEL = 0xCD7
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
            "cursor_available": True,
            "cursor_coords": (320, 180),
            "cursor_profile": CURSOR_PROFILE,
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
        return {register: self.engine.reg_read(register)
                for register in values}

    def _map_teb(self, initial_error: int = LAST_ERROR_SENTINEL) -> None:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((TEB_BASE, TEB_BASE + PAGE_SIZE))
        self.engine.mem_write(
            TEB_BASE + LAST_ERROR_OFFSET, struct.pack("<I", initial_error))

    def test_valid_pointer_writes_coordinates(self) -> None:
        esp = STACK_BASE + 0x100
        pt_addr = POINT_BASE + 0x20
        self._map_teb()
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, pt_addr))
        self.engine.mem_write(pt_addr, b"\xaa" * 8)
        initial = self._setup_cpu(esp)
        frame_before = bytes(self.engine.mem_read(esp, 8))
        last_error_before = bytes(self.engine.mem_read(
            TEB_BASE + LAST_ERROR_OFFSET, 4))

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
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
            initial[x86_const.UC_X86_REG_EFLAGS])

        for reg in OTHER_REGISTERS:
            self.assertEqual(
                self.engine.reg_read(reg), initial[reg])

        written = self.engine.mem_read(pt_addr, 8)
        x, y = struct.unpack("<ii", written)
        self.assertEqual((x, y), (320, 180))
        self.assertEqual(bytes(self.engine.mem_read(esp, 8)), frame_before)
        self.assertEqual(bytes(self.engine.mem_read(
            TEB_BASE + LAST_ERROR_OFFSET, 4)), last_error_before)
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["library"], "USER32.dll")
        self.assertEqual(api["name"], "GetCursorPos")
        self.assertEqual(api["import_index"], IMPORT_INDEX)
        self.assertEqual(api["tag"], 0xF0000000 + IMPORT_INDEX)
        self.assertEqual(api["call_ip"], IMPORT_IP)
        self.assertEqual(api["esp_before"], esp)
        self.assertEqual(api["argument_count"], 1)
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [pt_addr])
        self.assertEqual(api["result"], 1)
        self.assertEqual(api["profile"], "deterministic_cursor_fixture_v1")
        self.assertEqual(api["esp_after"], esp + 8)

    def test_null_pointer_sets_error_noaccess(self) -> None:
        esp = STACK_BASE + 0x100
        self._map_teb()
        self.state["cursor_available"] = False
        self.state.pop("cursor_coords")
        self.state.pop("cursor_profile")
        self.engine.mem_write(
            esp, struct.pack("<II", RETURN_ADDRESS, 0))
        initial = self._setup_cpu(esp)
        frame_before = bytes(self.engine.mem_read(esp, 8))

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
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
            initial[x86_const.UC_X86_REG_EFLAGS])
        for reg in OTHER_REGISTERS:
            self.assertEqual(self.engine.reg_read(reg), initial[reg])
        self.assertEqual(bytes(self.engine.mem_read(esp, 8)), frame_before)

        raw_error = self.engine.mem_read(TEB_BASE + LAST_ERROR_OFFSET, 4)
        error, = struct.unpack("<I", raw_error)
        self.assertEqual(error, ERROR_NOACCESS)
        self.assertEqual(len(self.state["api_calls"]), 1)
        self.assertEqual(self.state["api_calls"][0]["profile"], CURSOR_PROFILE)

    def test_missing_or_unavailable_snapshot_is_unsupported_without_side_effects(self) -> None:
        esp = STACK_BASE + 0x100
        pt_addr = POINT_BASE + 0x20
        cases = (
            ("availability_missing", "missing", {}),
            ("availability_false", False, {}),
            ("coordinates_missing", True, {"cursor_coords": None}),
            ("profile_missing", True, {"cursor_profile": None}),
        )
        for name, availability, changes in cases:
            with self.subTest(case=name):
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                if availability == "missing":
                    self.state.pop("cursor_available", None)
                else:
                    self.state["cursor_available"] = availability
                self.state["cursor_coords"] = (320, 180)
                self.state["cursor_profile"] = CURSOR_PROFILE
                self.state.update(changes)
                self.engine.mem_write(
                    esp, struct.pack("<II", RETURN_ADDRESS, pt_addr))
                self.engine.mem_write(pt_addr, b"\xA5" * 8)
                initial = self._setup_cpu(esp)
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                point_before = bytes(self.engine.mem_read(POINT_BASE, PAGE_SIZE))
                state_before = dict(self.state)

                handled = _cursor_query_import(
                    self.engine, x86_const, unicorn, self.row,
                    self.mapped_ranges, self.state)

                self.assertFalse(handled)
                self.assertEqual(self.state, state_before)
                for reg, value in initial.items():
                    self.assertEqual(self.engine.reg_read(reg), value)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(POINT_BASE, PAGE_SIZE)),
                                 point_before)
                self.assertEqual(self.state["api_calls"], [])
                self.assertFalse(self.state["resume"])

    def test_invalid_point_fault_precedes_unavailable_snapshot(self) -> None:
        esp = STACK_BASE + 0x100
        unmapped_pt = 0x00800000
        overflowing_pt = 0xFFFFFFFC
        cases = (
            ("unmapped", unmapped_pt, "write", 8),
            ("overflow", overflowing_pt, "write", 8),
        )
        for name, point, access, size in cases:
            with self.subTest(case=name):
                self.state["cursor_available"] = False
                self.state.pop("cursor_coords", None)
                self.state.pop("cursor_profile", None)
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.state.pop("target", None)
                self.state.pop("memory_fault", None)
                self.engine.mem_write(
                    esp, struct.pack("<II", RETURN_ADDRESS, point))
                initial = self._setup_cpu(esp)
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                point_before = bytes(self.engine.mem_read(POINT_BASE, PAGE_SIZE))

                handled = _cursor_query_import(
                    self.engine, x86_const, unicorn, self.row,
                    self.mapped_ranges, self.state)

                self.assertFalse(handled)
                self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
                self.assertEqual(self.state["target"], point)
                self.assertEqual(self.state["memory_fault"], {
                    "access": access, "address": point, "size": size,
                })
                self.assertEqual(self.state["api_calls"], [])
                self.assertFalse(self.state["resume"])
                for reg, value in initial.items():
                    self.assertEqual(self.engine.reg_read(reg), value)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(POINT_BASE, PAGE_SIZE)),
                                 point_before)

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
        self.state["cursor_available"] = False
        self.state.pop("cursor_coords")
        self.state.pop("cursor_profile")
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
