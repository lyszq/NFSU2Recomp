#!/usr/bin/env python3
"""Synthetic-memory tests for the headless GetWindowRect oracle."""
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

from window_oracle import _window_query_import


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
ERROR_INVALID_WINDOW_HANDLE = 1400
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000017
IMPORT_INDEX = 23
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


class WindowOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "tls_current_teb": TEB_BASE,
        }
        self.row = {
            "library": "USER32.dll",
            "name": "GetWindowRect",
            "index": IMPORT_INDEX,
        }
        self.write_frame(hwnd=0, rect=0xDEADBEEF)

    def write_frame(self, *, hwnd: int, rect: int, esp: int = STACK_BASE,
                    return_address: int = RETURN_ADDRESS) -> bytes:
        frame = struct.pack("<III", return_address, hwnd & 0xFFFFFFFF,
                            rect & 0xFFFFFFFF)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)
        return frame

    def set_registers(self, esp: int) -> None:
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.engine.reg_write(register, 0x11110000 + offset)

    def map_teb(self, *, permissions: int = unicorn.UC_PROT_ALL) -> int:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, permissions)
        self.mapped_ranges.append((TEB_BASE, TEB_BASE + PAGE_SIZE))
        address = TEB_BASE + LAST_ERROR_OFFSET
        self.engine.mem_write(address, struct.pack("<I", LAST_ERROR_SENTINEL))
        return address

    def call_import(self, *, row: dict[str, object] | None = None) -> bool:
        return _window_query_import(
            self.engine, x86_const, unicorn, row or self.row,
            self.mapped_ranges, self.state)

    def register_snapshot(self) -> dict[int, int]:
        return {register: self.engine.reg_read(register)
                for register in SNAPSHOT_REGISTERS}

    def assert_success_registers(self, *, esp: int = STACK_BASE,
                                 return_address: int = RETURN_ADDRESS) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         (esp + 12) & 0xFFFFFFFF)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         return_address)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         self.flags_before)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])

    def assert_no_side_effects(self, *, frame_address: int = STACK_BASE,
                               frame_size: int = 12) -> None:
        registers_before = self.register_snapshot()
        frame_before = bytes(self.engine.mem_read(frame_address, frame_size))
        state_before = dict(self.state)

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(frame_address, frame_size)),
                         frame_before)
        self.assertEqual(self.state, state_before)

    def assert_memory_fault_atomic(self, *, access: str, address: int,
                                   size: int, frame_address: int = STACK_BASE,
                                   frame_size: int = 12) -> None:
        registers_before = self.register_snapshot()
        frame_before = bytes(self.engine.mem_read(frame_address, frame_size))
        state_before = dict(self.state)

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(frame_address, frame_size)),
                         frame_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], address & 0xFFFFFFFF)
        self.assertEqual(self.state["memory_fault"], {
            "access": access, "address": address, "size": size,
        })
        self.assertEqual(self.state["api_calls"], state_before["api_calls"])
        self.assertFalse(self.state["resume"])

    def test_null_window_sets_last_error_and_preserves_poison_rect(self) -> None:
        last_error_address = self.map_teb()
        frame = self.write_frame(hwnd=0, rect=0xDEADBEEF)

        self.assertTrue(self.call_import())

        self.assert_success_registers()
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 12)), frame)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(last_error_address, 4))[0],
            ERROR_INVALID_WINDOW_HANDLE,
        )
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["library"], "USER32.dll")
        self.assertEqual(api["name"], "GetWindowRect")
        self.assertEqual(api["import_index"], IMPORT_INDEX)
        self.assertEqual(api["tag"], 0xF0000000 + IMPORT_INDEX)
        self.assertEqual(api["call_ip"], IMPORT_IP)
        self.assertEqual(api["esp_before"], STACK_BASE)
        self.assertEqual(api["argument_count"], 2)
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [0, 0xDEADBEEF])
        self.assertEqual(api["result"], 0)
        self.assertEqual(api["last_error_after"], ERROR_INVALID_WINDOW_HANDLE)
        self.assertEqual(api["outcome"], "invalid_window_handle")
        self.assertEqual(api["profile"], "headless_no_guest_window")
        self.assertEqual(api["esp_after"], STACK_BASE + 12)

    def test_null_or_unmapped_rect_pointer_is_ignored(self) -> None:
        last_error_address = self.map_teb()
        for rect in (0, 0x70000000):
            with self.subTest(rect=rect):
                self.write_frame(hwnd=0, rect=rect)
                self.state["api_calls"] = []
                self.state["resume"] = False

                self.assertTrue(self.call_import())

                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                                 RETURN_ADDRESS)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                                 STACK_BASE + 12)
                self.assertEqual(
                    struct.unpack("<I", self.engine.mem_read(
                        last_error_address, 4))[0], ERROR_INVALID_WINDOW_HANDLE)
                self.assertEqual(len(self.state["api_calls"]), 1)

    def test_nonzero_window_handle_is_unsupported_before_teb_or_rect_access(self) -> None:
        self.state["tls_current_teb"] = 0
        frame = self.write_frame(hwnd=0x1234, rect=0x70000000)
        registers_before = self.register_snapshot()

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 12)), frame)
        self.assertEqual(self.state["api_calls"], [])
        self.assertIsNone(self.state["status"])
        self.assertFalse(self.state["resume"])

    def test_wrong_library_or_export_is_unsupported_without_side_effects(self) -> None:
        rows = (
            {"library": "KERNEL32.dll", "name": "GetWindowRect",
             "index": IMPORT_INDEX},
            {"library": "USER32.dll", "name": "getwindowrect",
             "index": IMPORT_INDEX},
        )
        for row in rows:
            with self.subTest(row=row):
                registers_before = self.register_snapshot()
                frame_before = bytes(self.engine.mem_read(STACK_BASE, 12))

                self.assertFalse(self.call_import(row=row))

                self.assertEqual(self.register_snapshot(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 12)),
                                 frame_before)
                self.assertEqual(self.state["api_calls"], [])
                self.assertFalse(self.state["resume"])

    def test_unmapped_partial_and_unreadable_frames_stop_atomically(self) -> None:
        # Unmapped ESP.
        self.set_registers(0x00600000)
        self.assert_memory_fault_atomic(
            access="read", address=0x00600000, size=12,
            frame_address=STACK_BASE,
        )

        # Only 11 bytes are represented in the oracle's mapped-range contract.
        self.write_frame(hwnd=0, rect=0xDEADBEEF)
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + 11)]
        self.assert_memory_fault_atomic(
            access="read", address=STACK_BASE, size=12)

        # Unicorn still has the page mapped, but guest read permission is absent.
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_WRITE)
        self.assert_memory_fault_atomic(
            access="read", address=STACK_BASE, size=12)

    def test_overflowing_frame_stops_at_frame_base(self) -> None:
        high_page = 0xFFFFF000
        self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_write(0xFFFFFFF8, b"12345678")
        self.mapped_ranges.append((high_page, 0x100000000))
        self.set_registers(0xFFFFFFF8)

        self.assert_memory_fault_atomic(
            access="read", address=0xFFFFFFF8, size=12,
            frame_address=0xFFFFFFF8, frame_size=8)

    def test_zero_teb_is_an_api_state_stop_without_guest_mutation(self) -> None:
        self.state["tls_current_teb"] = 0
        registers_before = self.register_snapshot()
        frame_before = bytes(self.engine.mem_read(STACK_BASE, 12))
        state_before = dict(self.state)

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 12)), frame_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["target"], 0)
        self.assertEqual(self.state["api_state_fault"], {
            "api": "GetWindowRect", "address": 0,
            "reason": "current_teb_invalid",
        })
        self.assertEqual(self.state["api_calls"], state_before["api_calls"])
        self.assertFalse(self.state["resume"])

    def test_unmapped_and_readonly_last_error_targets_fault_atomically(self) -> None:
        address = TEB_BASE + LAST_ERROR_OFFSET
        self.assert_memory_fault_atomic(access="write", address=address, size=4)

        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((TEB_BASE, TEB_BASE + PAGE_SIZE))
        self.engine.mem_write(address, struct.pack("<I", LAST_ERROR_SENTINEL))
        self.assert_memory_fault_atomic(access="write", address=address, size=4)
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(address, 4))[0],
                         LAST_ERROR_SENTINEL)

    def test_teb_address_addition_overflow_faults_at_uint32_max(self) -> None:
        self.state["tls_current_teb"] = 0xFFFFFFE0
        self.assert_memory_fault_atomic(
            access="write", address=0xFFFFFFFF, size=4)

    def test_last_error_dword_width_overflow_faults_at_request_base(self) -> None:
        # FFFFFFCA + 0x34 = FFFFFFFE: the start is representable but the
        # requested four-byte write would extend two bytes past the address space.
        self.state["tls_current_teb"] = 0xFFFFFFCA
        self.assert_memory_fault_atomic(
            access="write", address=0xFFFFFFFE, size=4)

    def test_last_error_dword_at_top_of_address_space_is_valid(self) -> None:
        high_page = 0xFFFFF000
        self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((high_page, 0x100000000))
        last_error_address = 0xFFFFFFFC
        self.engine.mem_write(last_error_address, struct.pack("<I", 0x12345678))
        self.state["tls_current_teb"] = 0xFFFFFFC8

        self.assertTrue(self.call_import())

        self.assert_success_registers()
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(
            last_error_address, 4))[0], ERROR_INVALID_WINDOW_HANDLE)

    def test_last_error_write_aliasing_frame_uses_saved_frame_snapshot(self) -> None:
        for alias_offset in (0, 4):
            with self.subTest(alias_offset=alias_offset):
                self.write_frame(hwnd=0, rect=0xDEADBEEF)
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["tls_current_teb"] = (
                    STACK_BASE + alias_offset - LAST_ERROR_OFFSET)
                original_frame = struct.pack(
                    "<III", RETURN_ADDRESS, 0, 0xDEADBEEF)

                self.assertTrue(self.call_import())

                self.assert_success_registers()
                expected_frame = bytearray(original_frame)
                expected_frame[alias_offset:alias_offset + 4] = struct.pack(
                    "<I", ERROR_INVALID_WINDOW_HANDLE)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 12)),
                                 bytes(expected_frame))
                api = self.state["api_calls"][0]
                self.assertEqual(api["return_address"], RETURN_ADDRESS)
                self.assertEqual(api["arguments"], [0, 0xDEADBEEF])

    def test_get_system_metrics_swapbutton_returns_zero(self) -> None:
        row = {"library": "USER32.dll", "name": "GetSystemMetrics", "index": IMPORT_INDEX}
        frame = struct.pack("<II", RETURN_ADDRESS, 23)
        self.engine.mem_write(STACK_BASE, frame)
        self.set_registers(STACK_BASE)

        self.assertTrue(self.call_import(row=row))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), STACK_BASE + 8)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS), self.flags_before)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["name"], "GetSystemMetrics")
        self.assertEqual(api["arguments"], [23])
        self.assertEqual(api["result"], 0)
        self.assertEqual(api["esp_after"], STACK_BASE + 8)

    def test_get_system_metrics_screen_dimensions(self) -> None:
        row = {"library": "USER32.dll", "name": "GetSystemMetrics", "index": IMPORT_INDEX}
        metrics_cases = [
            (0, 640),    # SM_CXSCREEN
            (1, 480),    # SM_CYSCREEN
            (23, 0),     # SM_SWAPBUTTON
            (999, 0),    # unknown
        ]
        for metric, expected_result in metrics_cases:
            with self.subTest(metric=metric):
                self.state["api_calls"] = []
                self.state["resume"] = False
                frame = struct.pack("<II", RETURN_ADDRESS, metric)
                self.engine.mem_write(STACK_BASE, frame)
                self.set_registers(STACK_BASE)

                self.assertTrue(self.call_import(row=row))

                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), expected_result)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), STACK_BASE + 8)
                self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), RETURN_ADDRESS)

    def test_get_system_metrics_unmapped_frame_faults_atomically(self) -> None:
        row = {"library": "USER32.dll", "name": "GetSystemMetrics", "index": IMPORT_INDEX}
        self.set_registers(0x00600000)
        registers_before = self.register_snapshot()

        self.assertFalse(self.call_import(row=row))

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], 0x00600000)
        self.assertEqual(self.state["memory_fault"], {
            "access": "read", "address": 0x00600000, "size": 8,
        })
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])

    def test_get_system_metrics_wrong_library_is_unsupported(self) -> None:
        row = {"library": "KERNEL32.dll", "name": "GetSystemMetrics", "index": IMPORT_INDEX}
        frame = struct.pack("<II", RETURN_ADDRESS, 23)
        self.engine.mem_write(STACK_BASE, frame)
        self.set_registers(STACK_BASE)
        registers_before = self.register_snapshot()

        self.assertFalse(self.call_import(row=row))

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])


if __name__ == "__main__":
    unittest.main()
