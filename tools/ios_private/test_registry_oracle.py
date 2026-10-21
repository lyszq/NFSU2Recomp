#!/usr/bin/env python3
"""Synthetic-memory tests for the bounded RegOpenKeyA oracle contract."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(__file__).resolve().parent
PRIVATE_DEPS = ROOT / "out" / "private-deps"
for path in (ROOT / "tools", PRIVATE, PRIVATE_DEPS):
    if path.is_dir():
        sys.path.insert(0, str(path))

import unicorn
from unicorn import x86_const

from registry_oracle import (
    REGISTRY_PROFILE,
    REGISTRY_ROOTS,
    _registry_import,
)


STRUCT_BASE = 0x00300000
STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000009
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
OTHER_REGISTERS = (
    x86_const.UC_X86_REG_EBX,
    x86_const.UC_X86_REG_ECX,
    x86_const.UC_X86_REG_EDX,
    x86_const.UC_X86_REG_ESI,
    x86_const.UC_X86_REG_EDI,
    x86_const.UC_X86_REG_EBP,
)
RETURN_REGISTERS = (
    x86_const.UC_X86_REG_EAX,
    x86_const.UC_X86_REG_EIP,
    x86_const.UC_X86_REG_ESP,
    x86_const.UC_X86_REG_EFLAGS,
)


class RegistryOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(STRUCT_BASE, PAGE_SIZE * 2, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (STRUCT_BASE, STRUCT_BASE + PAGE_SIZE * 2),
        ]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
        }
        self.row = {
            "library": "ADVAPI32.dll",
            "name": "RegOpenKeyA",
            "index": 9,
        }
        self.write_import_frame(0x80000001, 0, STRUCT_BASE + 0x100)

    def write_import_frame(self, root: int, subkey: int, output: int,
                           *, esp: int = STACK_BASE,
                           return_address: int = RETURN_ADDRESS) -> bytes:
        frame = struct.pack("<IIII", return_address, root, subkey, output)
        self.engine.mem_write(esp, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.engine.reg_write(register, 0x11110000 + offset)
        return frame

    def call_registry(self, *, row: dict[str, object] | None = None) -> bool:
        return _registry_import(
            self.engine, x86_const, unicorn, row or self.row,
            self.mapped_ranges, self.state)

    def register_snapshot(self) -> dict[int, int]:
        registers = RETURN_REGISTERS + OTHER_REGISTERS
        return {register: self.engine.reg_read(register) for register in registers}

    def assert_success_frame(self, expected_result: int) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         expected_result)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         STACK_BASE + 16)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         self.flags_before)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])

    def assert_memory_stop_is_atomic(self, *, access: str, address: int,
                                     size: int, esp: int = STACK_BASE,
                                     extra_watches: tuple[tuple[int, int], ...] = ()) -> None:
        registers_before = self.register_snapshot()
        watched = [(esp, 16), (STRUCT_BASE + 0x100, 32), *extra_watches]
        memory_before = [bytes(self.engine.mem_read(start, length))
                         for start, length in watched]

        handled = self.call_registry()

        self.assertFalse(handled)
        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(
            [bytes(self.engine.mem_read(start, length)) for start, length in watched],
            memory_before,
        )
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], address & 0xFFFFFFFF)
        self.assertEqual(self.state["memory_fault"], {
            "access": access, "address": address, "size": size,
        })
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])

    def test_all_five_predefined_roots_and_empty_name_aliases(self) -> None:
        for index, root in enumerate(sorted(REGISTRY_ROOTS)):
            for subkey in (0, STRUCT_BASE + 0x200):
                with self.subTest(root=hex(root), subkey=subkey):
                    if subkey:
                        self.engine.mem_write(subkey, b"\0")
                    self.write_import_frame(root, subkey, STRUCT_BASE + 0x100)

                    self.assertTrue(self.call_registry())

                    self.assert_success_frame(0)
                    self.assertEqual(
                        struct.unpack("<I", self.engine.mem_read(
                            STRUCT_BASE + 0x100, 4))[0], root)
                    self.assertEqual(self.state["api_calls"][-1]["profile"],
                                     REGISTRY_PROFILE)
                    self.assertEqual(self.state["api_calls"][-1]["result"], 0)
                    self.assertEqual(
                        self.state["api_calls"][-1]["arguments"], {
                            "hKey": root,
                            "lpSubKey": subkey,
                            "phkResult": STRUCT_BASE + 0x100,
                        })
                    self.assertEqual(self.state["api_calls"][-1]["return_address"],
                                     RETURN_ADDRESS)
                    self.assertEqual(self.state["api_calls"][-1]["argument_count"], 3)
                    self.state["api_calls"].clear()
                    self.state["resume"] = False

    def test_nonempty_keys_are_not_invented_and_output_is_null(self) -> None:
        subkey = STRUCT_BASE + 0x200
        output = STRUCT_BASE + 0x100
        self.engine.mem_write(subkey, b"Software\\UnknownVendor\\Key\0")
        self.engine.mem_write(output, struct.pack("<I", 0xDEADBEEF))
        self.write_import_frame(0x80000002, subkey, output)

        self.assertTrue(self.call_registry())

        self.assert_success_frame(2)
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(output, 4))[0], 0)
        api = self.state["api_calls"][-1]
        self.assertEqual(api["outcome"], "key_not_found")
        self.assertEqual(api["subkey"], "Software\\UnknownVendor\\Key")
        self.assertEqual(api["output_handle"], 0)

    def test_invalid_root_returns_invalid_handle_and_null_output(self) -> None:
        output = STRUCT_BASE + 0x100
        self.engine.mem_write(output, struct.pack("<I", 0xDEADBEEF))
        self.write_import_frame(0x80000004, 0, output)

        self.assertTrue(self.call_registry())

        self.assert_success_frame(6)
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(output, 4))[0], 0)
        self.assertEqual(self.state["api_calls"][-1]["outcome"], "invalid_handle")

    def test_dll_case_alias_and_output_aliasing_return_address_use_frame_snapshot(self) -> None:
        root = 0x80000005
        esp = STACK_BASE
        frame = self.write_import_frame(root, 0, esp)

        self.assertTrue(self.call_registry(row={
            "library": "Advapi32.DLL", "name": "RegOpenKeyA", "index": 9,
        }))

        self.assert_success_frame(0)
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(esp, 4))[0], root)
        api = self.state["api_calls"][-1]
        self.assertEqual(api["return_address"], struct.unpack_from("<I", frame)[0])
        self.assertEqual(api["arguments"]["hKey"], root)
        self.assertEqual(api["output_handle"], root)

    def test_output_aliasing_subkey_is_written_only_after_name_snapshot(self) -> None:
        alias = STRUCT_BASE + 0x200
        self.engine.mem_write(alias, b"MissingKey\0")
        self.write_import_frame(0x80000001, alias, alias)

        self.assertTrue(self.call_registry())

        self.assert_success_frame(2)
        self.assertEqual(struct.unpack("<I", self.engine.mem_read(alias, 4))[0], 0)
        api = self.state["api_calls"][-1]
        self.assertEqual(api["subkey"], "MissingKey")
        self.assertEqual(api["output_handle"], 0)

    def test_invalid_handle_still_preflights_output_pointer(self) -> None:
        self.write_import_frame(0x80000004, 0, 0xFFFFFFFE)
        self.assert_memory_stop_is_atomic(
            access="write", address=0xFFFFFFFE, size=4)

    def test_invalid_handle_still_preflights_subkey_before_output(self) -> None:
        output = STRUCT_BASE + 0x100
        self.engine.mem_write(output, struct.pack("<I", 0xDEADBEEF))
        self.write_import_frame(0x80000004, 0x00600000, output)
        self.assert_memory_stop_is_atomic(
            access="read", address=0x00600000, size=1)

    def test_unmapped_subkey_stops_before_output_write_or_register_changes(self) -> None:
        output = STRUCT_BASE + 0x100
        self.engine.mem_write(output, struct.pack("<I", 0xDEADBEEF))
        self.write_import_frame(0x80000001, 0x00600000, output)
        self.assert_memory_stop_is_atomic(
            access="read", address=0x00600000, size=1)

    def test_null_or_unmapped_output_stops_without_guest_mutation(self) -> None:
        for output in (0, 0x00600000):
            with self.subTest(output=hex(output)):
                self.write_import_frame(0x80000001, 0, output)
                self.assert_memory_stop_is_atomic(
                    access="write", address=output, size=4)

    def test_readonly_output_stops_without_guest_mutation(self) -> None:
        readonly = 0x00600000
        self.engine.mem_map(readonly, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((readonly, readonly + PAGE_SIZE))
        self.write_import_frame(0x80000001, 0, readonly)
        self.assert_memory_stop_is_atomic(
            access="write", address=readonly, size=4,
            extra_watches=((readonly, 4),))

    def test_unmapped_frame_stops_atomically(self) -> None:
        esp = 0x00601000
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        registers_before = self.register_snapshot()

        self.assertFalse(self.call_registry())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], esp)
        self.assertEqual(self.state["memory_fault"], {
            "access": "read", "address": esp, "size": 16,
        })
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])

    def test_partial_frame_mapping_still_requires_full_sixteen_byte_snapshot(self) -> None:
        self.mapped_ranges[0] = (STACK_BASE, STACK_BASE + 12)
        self.assert_memory_stop_is_atomic(
            access="read", address=STACK_BASE, size=16)

    def test_subkey_address_wrap_fault_clamps_to_last_guest_byte(self) -> None:
        high_page = 0xFFFFF000
        self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.mapped_ranges.append((high_page, 0x100000000))
        self.engine.mem_write(0xFFFFFFFF, b"X")
        self.write_import_frame(0x80000001, 0xFFFFFFFF, STRUCT_BASE + 0x100)

        self.assert_memory_stop_is_atomic(
            access="read", address=0xFFFFFFFF, size=1,
            extra_watches=((0xFFFFFFFF, 1),))

    def test_subkey_scan_limit_accepts_last_byte_nul_but_rejects_unterminated(self) -> None:
        start = STRUCT_BASE + 0x1000
        self.engine.mem_write(start, b"K" * 4095 + b"\0")
        self.write_import_frame(0x80000001, start, STRUCT_BASE + 0x100)

        self.assertTrue(self.call_registry())
        self.assert_success_frame(2)
        self.assertEqual(len(self.state["api_calls"][-1]["subkey"]), 4095)

        self.state["api_calls"].clear()
        self.state["resume"] = False
        self.engine.mem_write(start, b"K" * 4096)
        before_memory = bytes(self.engine.mem_read(start, 4096))
        self.write_import_frame(0x80000001, start, STRUCT_BASE + 0x100)
        before_registers = self.register_snapshot()

        self.assertFalse(self.call_registry())

        self.assertEqual(self.register_snapshot(), before_registers)
        self.assertEqual(bytes(self.engine.mem_read(start, 4096)), before_memory)
        self.assertEqual(self.state["api_calls"], [])
        self.assertIsNone(self.state["status"])
        self.assertFalse(self.state["resume"])

    def test_other_imports_and_export_spellings_are_unsupported_without_effects(self) -> None:
        cases = (
            {"library": "KERNEL32.dll", "name": "RegOpenKeyA", "index": 9},
            {"library": "ADVAPI32.dll", "name": "RegOpenKeyW", "index": 9},
        )
        for row in cases:
            with self.subTest(row=row):
                registers_before = self.register_snapshot()
                frame_before = bytes(self.engine.mem_read(STACK_BASE, 16))
                output_before = bytes(self.engine.mem_read(STRUCT_BASE + 0x100, 4))

                self.assertFalse(self.call_registry(row=row))

                self.assertEqual(self.register_snapshot(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 16)),
                                 frame_before)
                self.assertEqual(bytes(self.engine.mem_read(STRUCT_BASE + 0x100, 4)),
                                 output_before)
                self.assertEqual(self.state["api_calls"], [])
                self.assertIsNone(self.state["status"])
                self.assertFalse(self.state["resume"])


if __name__ == "__main__":
    unittest.main()
