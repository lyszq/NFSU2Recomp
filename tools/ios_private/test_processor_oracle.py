#!/usr/bin/env python3
"""Synthetic-memory tests for the bounded processor-feature oracle."""
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

from startup_oracle import _is_processor_feature_present


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000015
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
KNOWN_FEATURE = 7  # PF_3DNOW_INSTRUCTIONS_AVAILABLE, answered false.
SUPPORTED_TRUE_FEATURES = (6, 10)  # SSE and SSE2, from CPUID EDX bits 25/26.
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
LAST_ERROR_SENTINEL = 0x76543210
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


class ProcessorFeatureOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        # Deliberately do not map a TEB: this import has no LastError contract.
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
        }
        self.row = {
            "library": "KERNEL32.dll",
            "name": "IsProcessorFeaturePresent",
            "index": 21,
        }
        self.write_frame(KNOWN_FEATURE)

    def write_frame(self, feature: int, *, esp: int = STACK_BASE,
                    return_address: int = RETURN_ADDRESS) -> bytes:
        frame = struct.pack("<II", return_address, feature & 0xFFFFFFFF)
        self.engine.mem_write(esp, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.engine.reg_write(register, 0x11110000 + offset)
        return frame

    def call_import(self, *, row: dict[str, object] | None = None) -> bool:
        return _is_processor_feature_present(
            self.engine, x86_const, unicorn, row or self.row,
            self.mapped_ranges, self.state)

    def register_snapshot(self) -> dict[int, int]:
        registers = RETURN_REGISTERS + OTHER_REGISTERS
        return {register: self.engine.reg_read(register) for register in registers}

    def assert_success_frame(self, *, expected_eax: int) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), expected_eax)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         STACK_BASE + 8)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         self.flags_before)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])

    def assert_unsupported_unchanged(self, *, row: dict[str, object] | None = None,
                                    feature: int = KNOWN_FEATURE) -> None:
        self.write_frame(feature)
        registers_before = self.register_snapshot()
        frame_before = bytes(self.engine.mem_read(STACK_BASE, 8))

        self.assertFalse(self.call_import(row=row))

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame_before)
        self.assertEqual(self.state["api_calls"], [])
        self.assertIsNone(self.state["status"])
        self.assertFalse(self.state["resume"])

    def test_known_feature_seven_returns_false_and_records_profile(self) -> None:
        frame = self.write_frame(KNOWN_FEATURE)

        self.assertTrue(self.call_import())

        self.assert_success_frame(expected_eax=0)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame)
        self.assertNotIn("last_error", self.state)
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["library"], "KERNEL32.dll")
        self.assertEqual(api["name"], "IsProcessorFeaturePresent")
        self.assertEqual(api["import_index"], 21)
        self.assertEqual(api["tag"], IMPORT_IP)
        self.assertEqual(api["call_ip"], IMPORT_IP)
        self.assertEqual(api["esp_before"], STACK_BASE)
        self.assertEqual(api["argument_count"], 1)
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [KNOWN_FEATURE])
        self.assertEqual(api["result"], 0)
        self.assertEqual(api["profile"], "upstream_static_x86_006d8")
        self.assertEqual(api["esp_after"], STACK_BASE + 8)

    def test_sse_features_six_and_ten_return_true_without_side_effects(self) -> None:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        last_error_address = TEB_BASE + LAST_ERROR_OFFSET

        for feature in SUPPORTED_TRUE_FEATURES:
            with self.subTest(feature=feature):
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.engine.mem_write(
                    last_error_address,
                    struct.pack("<I", LAST_ERROR_SENTINEL),
                )
                frame = self.write_frame(feature)
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                teb_before = bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE))

                self.assertTrue(self.call_import())

                self.assert_success_frame(expected_eax=1)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE)),
                                 teb_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame)
                self.assertEqual(
                    struct.unpack("<I", self.engine.mem_read(
                        last_error_address, 4))[0], LAST_ERROR_SENTINEL)

                self.assertEqual(len(self.state["api_calls"]), 1)
                api = self.state["api_calls"][0]
                self.assertEqual(api["library"], "KERNEL32.dll")
                self.assertEqual(api["name"], "IsProcessorFeaturePresent")
                self.assertEqual(api["import_index"], 21)
                self.assertEqual(api["tag"], IMPORT_IP)
                self.assertEqual(api["call_ip"], IMPORT_IP)
                self.assertEqual(api["esp_before"], STACK_BASE)
                self.assertEqual(api["argument_count"], 1)
                self.assertEqual(api["return_address"], RETURN_ADDRESS)
                self.assertEqual(api["arguments"], [feature])
                self.assertEqual(api["result"], 1)
                self.assertEqual(api["profile"], "upstream_static_x86_006d8")
                self.assertEqual(api["esp_after"], STACK_BASE + 8)

    def test_last_error_storage_is_preserved(self) -> None:
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        last_error_address = TEB_BASE + LAST_ERROR_OFFSET
        self.engine.mem_write(last_error_address,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.write_frame(KNOWN_FEATURE)

        self.assertTrue(self.call_import())

        self.assert_success_frame(expected_eax=0)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(last_error_address, 4))[0],
            LAST_ERROR_SENTINEL,
        )

    def test_unknown_queries_are_strictly_unsupported_without_side_effects(self) -> None:
        for feature in (0, 8, 0xFFFFFFFF):
            with self.subTest(feature=feature):
                self.assert_unsupported_unchanged(feature=feature)

    def test_wrong_library_or_export_is_unsupported_without_side_effects(self) -> None:
        rows = (
            {"library": "ADVAPI32.dll", "name": "IsProcessorFeaturePresent",
             "index": 21},
            {"library": "KERNEL32.dll", "name": "IsDebuggerPresent",
             "index": 21},
        )
        for row in rows:
            with self.subTest(row=row):
                self.assert_unsupported_unchanged(row=row)

    def assert_frame_fault_atomic(self, *, esp: int, address: int,
                                  mapped_ranges: list[tuple[int, int]] | None = None,
                                  protect: int | None = None) -> None:
        if esp == STACK_BASE:
            self.write_frame(KNOWN_FEATURE, esp=esp)
        else:
            self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
            self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
            self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
            self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
            self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)
            for offset, register in enumerate(OTHER_REGISTERS):
                self.engine.reg_write(register, 0x11110000 + offset)
        frame_before = (bytes(self.engine.mem_read(esp, 8))
                        if esp == STACK_BASE else None)
        if esp == 0xFFFFFFFC:
            high_page = 0xFFFFF000
            self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_ALL)
            self.engine.mem_write(esp, struct.pack("<I", RETURN_ADDRESS))
            self.mapped_ranges.append((high_page, 0x100000000))
            frame_before = bytes(self.engine.mem_read(esp, 4))
        if protect is not None:
            self.engine.mem_protect(STACK_BASE, PAGE_SIZE, protect)
        if mapped_ranges is not None:
            self.mapped_ranges = mapped_ranges
        registers_before = self.register_snapshot()

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        if frame_before is not None:
            if protect is not None:
                self.engine.mem_protect(STACK_BASE, PAGE_SIZE,
                                        unicorn.UC_PROT_ALL)
            frame_size = 4 if esp == 0xFFFFFFFC else 8
            self.assertEqual(bytes(self.engine.mem_read(esp, frame_size)),
                             frame_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], address & 0xFFFFFFFF)
        self.assertEqual(self.state["memory_fault"], {
            "access": "read", "address": address, "size": 8,
        })
        self.assertFalse(self.state["resume"])

    def test_unmapped_or_overflowing_frame_stops_at_frame_base_atomically(self) -> None:
        self.assert_frame_fault_atomic(esp=0x00600000, address=0x00600000)

        self.state = {
            "last_ip": IMPORT_IP, "api_calls": [], "resume": False,
            "status": None,
        }
        self.assert_frame_fault_atomic(esp=0xFFFFFFFC, address=0xFFFFFFFC)

    def test_partial_frame_mapping_requires_full_eight_byte_read(self) -> None:
        self.assert_frame_fault_atomic(
            esp=STACK_BASE, address=STACK_BASE,
            mapped_ranges=[(STACK_BASE, STACK_BASE + 4)])

    def test_unreadable_frame_stops_without_register_or_memory_mutation(self) -> None:
        self.assert_frame_fault_atomic(
            esp=STACK_BASE, address=STACK_BASE,
            protect=unicorn.UC_PROT_WRITE)


if __name__ == "__main__":
    unittest.main()
