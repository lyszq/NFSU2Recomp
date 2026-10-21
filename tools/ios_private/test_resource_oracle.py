#!/usr/bin/env python3
"""Synthetic-memory tests for the evidence-gated LoadIconA oracle."""
from __future__ import annotations

from pathlib import Path
from copy import deepcopy
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

from resource_oracle import (
    ERROR_RESOURCE_TYPE_NOT_FOUND,
    CURSOR_IMPORT_NAME,
    IDI_APPLICATION_RESOURCE_ID,
    MISSING_ICON_PROFILE,
    OCR_NORMAL_RESOURCE_ID,
    SHARED_CURSOR_PROFILE,
    USER_OBJECT_CAPACITY,
    USER_OBJECT_HANDLE_BASE,
    _resource_import,
)


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
TEB_BASE = 0x00C00000
LAST_ERROR_OFFSET = 0x34
RETURN_ADDRESS = 0x00123456
IMPORT_IP = 0xF0000044
IMPORT_INDEX = 68
IMAGE_BASE = 0x00400000
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


class ResourceOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + PAGE_SIZE),
        ]
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "tls_current_teb": TEB_BASE,
            "resource_image_base": IMAGE_BASE,
            "resource_missing_application_icon": True,
            "user_objects": {},
        }
        self.row = {
            "library": "USER32.dll",
            "name": "LoadIconA",
            "index": IMPORT_INDEX,
        }
        self.cursor_row = {
            "library": "USER32.dll",
            "name": CURSOR_IMPORT_NAME,
            "index": IMPORT_INDEX + 1,
        }
        self.write_frame()

    def write_frame(self, *, esp: int = STACK_BASE + 0x100,
                    instance: int = IMAGE_BASE,
                    icon_name: int = IDI_APPLICATION_RESOURCE_ID,
                    return_address: int = RETURN_ADDRESS) -> bytes:
        frame = struct.pack("<III", return_address, instance, icon_name)
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

    def call_import(self, *, row: dict[str, object] | None = None) -> bool:
        return _resource_import(
            self.engine, x86_const, unicorn, row or self.row,
            self.mapped_ranges, self.state)

    def registers(self) -> dict[int, int]:
        return {register: self.engine.reg_read(register)
                for register in SNAPSHOT_REGISTERS}

    def assert_completed_call(self, *, esp: int = STACK_BASE + 0x100,
                              return_address: int = RETURN_ADDRESS) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         return_address)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         (esp + 12) & 0xFFFFFFFF)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         FLAGS_SENTINEL)
        for offset, register in enumerate(OTHER_REGISTERS):
            self.assertEqual(self.engine.reg_read(register), 0x11110000 + offset)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])

    def test_measured_missing_numeric_icon_sets_last_error_and_returns_null(self) -> None:
        self.engine.mem_write(
            TEB_BASE + LAST_ERROR_OFFSET,
            struct.pack("<I", LAST_ERROR_SENTINEL))
        frame_before = bytes(self.engine.mem_read(STACK_BASE + 0x100, 12))
        registers_before = self.registers()

        self.assertTrue(self.call_import())

        self.assert_completed_call()
        for register in OTHER_REGISTERS:
            self.assertEqual(self.engine.reg_read(register), registers_before[register])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         registers_before[x86_const.UC_X86_REG_EFLAGS])
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE + 0x100, 12)),
                         frame_before)
        error, = struct.unpack("<I", self.engine.mem_read(
            TEB_BASE + LAST_ERROR_OFFSET, 4))
        self.assertEqual(error, ERROR_RESOURCE_TYPE_NOT_FOUND)
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["library"], "USER32.dll")
        self.assertEqual(api["name"], "LoadIconA")
        self.assertEqual(api["import_index"], IMPORT_INDEX)
        self.assertEqual(api["tag"], 0xF0000000 + IMPORT_INDEX)
        self.assertEqual(api["call_ip"], IMPORT_IP)
        self.assertEqual(api["esp_before"], STACK_BASE + 0x100)
        self.assertEqual(api["argument_count"], 2)
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [IMAGE_BASE, IDI_APPLICATION_RESOURCE_ID])
        self.assertEqual(api["result"], 0)
        self.assertEqual(api["last_error_after"], ERROR_RESOURCE_TYPE_NOT_FOUND)
        self.assertEqual(api["outcome"], "resource_not_found")
        self.assertEqual(api["profile"], MISSING_ICON_PROFILE)
        self.assertEqual(api["esp_after"], STACK_BASE + 0x10C)

    def test_readonly_frame_is_valid_input_with_separate_writable_teb(self) -> None:
        esp = STACK_BASE + 0x100
        frame = self.write_frame(esp=esp)
        self.engine.mem_write(
            TEB_BASE + LAST_ERROR_OFFSET,
            struct.pack("<I", LAST_ERROR_SENTINEL))
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        registers_before = self.registers()

        self.assertTrue(self.call_import())

        self.assert_completed_call(esp=esp)
        self.assertEqual(bytes(self.engine.mem_read(esp, 12)), frame)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         registers_before[x86_const.UC_X86_REG_EFLAGS])
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)

    def test_last_error_aliases_frame_but_return_address_uses_snapshot(self) -> None:
        esp = STACK_BASE + 0x100
        frame = self.write_frame(esp=esp, return_address=0x76543210)
        self.state["tls_current_teb"] = esp - LAST_ERROR_OFFSET

        self.assertTrue(self.call_import())

        self.assert_completed_call(esp=esp, return_address=0x76543210)
        self.assertEqual(self.engine.mem_read(esp, 4),
                         struct.pack("<I", ERROR_RESOURCE_TYPE_NOT_FOUND))
        self.assertEqual(self.engine.mem_read(esp + 4, 8), frame[4:])
        self.assertEqual(self.state["api_calls"][0]["return_address"],
                         0x76543210)

    def test_missing_resource_proof_or_unmatched_resource_is_unsupported(self) -> None:
        cases = (
            ("proof_missing", {"resource_missing_application_icon": None}),
            ("proof_false", {"resource_missing_application_icon": False}),
            ("proof_nonboolean", {"resource_missing_application_icon": 1}),
            ("base_missing", {"resource_image_base": None}),
            ("base_zero", {"resource_image_base": 0}),
            ("base_boolean", {"resource_image_base": True}),
            ("base_string", {"resource_image_base": "0x00400000"}),
            ("wrong_module", {"frame_instance": IMAGE_BASE + 0x1000}),
            ("named_resource", {"frame_icon": 0x00401000}),
            ("other_integer", {"frame_icon": 1}),
        )
        esp = STACK_BASE + 0x100
        for name, changes in cases:
            with self.subTest(case=name):
                self.state["resource_missing_application_icon"] = True
                self.state["resource_image_base"] = IMAGE_BASE
                instance = IMAGE_BASE
                icon = IDI_APPLICATION_RESOURCE_ID
                for key, value in changes.items():
                    if key == "frame_instance":
                        instance = value
                    elif key == "frame_icon":
                        icon = value
                    else:
                        self.state[key] = value
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.state.pop("target", None)
                self.state.pop("memory_fault", None)
                self.write_frame(esp=esp, instance=instance, icon_name=icon)
                self.engine.mem_write(
                    TEB_BASE + LAST_ERROR_OFFSET,
                    struct.pack("<I", LAST_ERROR_SENTINEL))
                registers_before = self.registers()
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                teb_before = bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE))
                state_before = dict(self.state)

                self.assertFalse(self.call_import())

                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE)),
                                 teb_before)
                self.assertEqual(self.state, state_before)

    def test_wrong_library_or_export_is_ignored_before_frame_access(self) -> None:
        self.set_registers(0x00800000)
        registers_before = self.registers()
        state_before = dict(self.state)
        rows = (
            {"library": "KERNEL32.dll", "name": "LoadIconA", "index": IMPORT_INDEX},
            {"library": "USER32.dll", "name": "LoadIconW", "index": IMPORT_INDEX},
        )
        for row in rows:
            with self.subTest(row=row):
                self.assertFalse(self.call_import(row=row))
                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(self.state, state_before)

    def test_frame_faults_are_atomic(self) -> None:
        cases = (
            ("unmapped", 0x00800000, 12, None),
            ("partial", STACK_BASE + PAGE_SIZE - 8, 8, None),
            ("nonreadable", STACK_BASE + 0x100, 12, unicorn.UC_PROT_WRITE),
        )
        for name, esp, readable_size, protection in cases:
            with self.subTest(case=name):
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.state.pop("target", None)
                self.state.pop("memory_fault", None)
                if name == "partial":
                    self.engine.mem_write(esp, b"\xA5" * readable_size)
                stack_before = (bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                                if name == "nonreadable" else None)
                if protection is not None:
                    self.engine.mem_protect(STACK_BASE, PAGE_SIZE, protection)
                self.set_registers(esp)
                registers_before = self.registers()
                state_before = dict(self.state)

                self.assertFalse(self.call_import())

                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
                self.assertEqual(self.state["target"], esp)
                self.assertEqual(self.state["memory_fault"], {
                    "access": "read", "address": esp, "size": 12,
                })
                self.assertEqual(self.state["api_calls"], state_before["api_calls"])
                self.assertFalse(self.state["resume"])
                if stack_before is not None:
                    self.engine.mem_protect(STACK_BASE, PAGE_SIZE,
                                            unicorn.UC_PROT_ALL)
                    self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                     stack_before)
                if protection is not None:
                    self.engine.mem_protect(STACK_BASE, PAGE_SIZE,
                                            unicorn.UC_PROT_ALL)

    def test_stack_extent_overflow_faults_at_stack_base(self) -> None:
        high_page = 0xFFFFF000
        self.engine.mem_map(high_page, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((high_page, 0x100000000))
        esp = 0xFFFFFFF8
        self.engine.mem_write(esp, struct.pack("<II", RETURN_ADDRESS, IMAGE_BASE))
        self.set_registers(esp)
        registers_before = self.registers()
        state_before = dict(self.state)

        self.assertFalse(self.call_import())

        self.assertEqual(self.registers(), registers_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], esp)
        self.assertEqual(self.state["memory_fault"], {
            "access": "read", "address": esp, "size": 12,
        })
        self.assertEqual(self.state["api_calls"], state_before["api_calls"])
        self.assertFalse(self.state["resume"])

    def test_last_error_faults_and_invalid_teb_do_not_complete_call(self) -> None:
        esp = STACK_BASE + 0x100
        overflow_cases = (
            # ERROR address is representable, but the DWORD extends past 4 GiB.
            (0xFFFFFFA9, 0xFFFFFFDD),
            (0xFFFFFFCB, 0xFFFFFFFF),
            # TEB + 0x34 itself overflows; fault clamps to the top address.
            (0xFFFFFFCC, 0xFFFFFFFF),
        )
        for name, teb, fault_address in (
                ("unmapped", 0x00D00000, 0x00D00034),
                ("readonly", TEB_BASE, TEB_BASE + LAST_ERROR_OFFSET),
                *((f"overflow_{index}", teb, address)
                  for index, (teb, address) in enumerate(overflow_cases))):
            with self.subTest(case=name):
                self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
                self.engine.mem_protect(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
                self.state["tls_current_teb"] = teb
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.state.pop("target", None)
                self.state.pop("memory_fault", None)
                self.write_frame(esp=esp)
                if name == "readonly":
                    self.engine.mem_write(fault_address,
                                          struct.pack("<I", LAST_ERROR_SENTINEL))
                    self.engine.mem_protect(TEB_BASE, PAGE_SIZE,
                                            unicorn.UC_PROT_READ)
                registers_before = self.registers()
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                teb_before = bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE))

                self.assertFalse(self.call_import())

                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
                self.assertEqual(self.state["target"], fault_address)
                self.assertEqual(self.state["memory_fault"], {
                    "access": "write", "address": fault_address, "size": 4,
                })
                self.assertEqual(self.state["api_calls"], [])
                self.assertFalse(self.state["resume"])
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE)),
                                 teb_before)

        self.state["tls_current_teb"] = 0
        self.state["api_calls"] = []
        self.state["resume"] = False
        self.state["status"] = None
        self.state.pop("target", None)
        self.state.pop("api_state_fault", None)
        self.write_frame(esp=esp)
        registers_before = self.registers()
        stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))

        self.assertFalse(self.call_import())

        self.assertEqual(self.registers(), registers_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["target"], 0)
        self.assertEqual(self.state["api_state_fault"], {
            "api": "LoadIconA", "address": 0,
            "reason": "current_teb_invalid",
        })
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                         stack_before)

    def test_null_module_system_cursor_is_a_typed_virtual_object_without_teb(self) -> None:
        esp = STACK_BASE + 0x100
        frame = self.write_frame(
            esp=esp, instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)
        last_error_address = TEB_BASE + LAST_ERROR_OFFSET
        self.engine.mem_write(last_error_address,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.state["tls_current_teb"] = 0
        self.mapped_ranges = [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.engine.mem_protect(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_NONE)
        registers_before = self.registers()

        self.assertTrue(self.call_import(row=self.cursor_row))

        handle = USER_OBJECT_HANDLE_BASE
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), handle)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp + 12)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         registers_before[x86_const.UC_X86_REG_EFLAGS])
        for register in OTHER_REGISTERS:
            self.assertEqual(self.engine.reg_read(register), registers_before[register])
        self.assertEqual(bytes(self.engine.mem_read(esp, 12)), frame)
        self.assertEqual(self.state["user_objects"], {
            handle: {
                "handle": handle,
                "kind": "CURSOR",
                "origin": "SYSTEM_SHARED",
                "system_id": OCR_NORMAL_RESOURCE_ID,
                "module": 0,
                "shared": True,
            },
        })
        self.assertEqual(len(self.state["api_calls"]), 1)
        api = self.state["api_calls"][0]
        self.assertEqual(api["name"], CURSOR_IMPORT_NAME)
        self.assertEqual(api["arguments"], [0, OCR_NORMAL_RESOURCE_ID])
        self.assertEqual(api["result"], handle)
        self.assertEqual(api["profile"], SHARED_CURSOR_PROFILE)
        self.assertEqual(api["esp_after"], esp + 12)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])

        self.engine.mem_protect(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        error, = struct.unpack("<I", self.engine.mem_read(last_error_address, 4))
        self.assertEqual(error, LAST_ERROR_SENTINEL)
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)

    def test_shared_cursor_reloads_return_stable_handle(self) -> None:
        self.state["tls_current_teb"] = 0
        self.state["user_objects"] = {}
        esp = STACK_BASE + 0x100
        self.write_frame(esp=esp, instance=0,
                         icon_name=OCR_NORMAL_RESOURCE_ID)

        self.assertTrue(self.call_import(row=self.cursor_row))
        first_handle = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        table_after_first = dict(self.state["user_objects"])

        second_return = 0x0056789A
        self.write_frame(esp=esp + 0x20, instance=0,
                         icon_name=OCR_NORMAL_RESOURCE_ID,
                         return_address=second_return)
        self.assertTrue(self.call_import(row=self.cursor_row))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         first_handle)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         second_return)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         esp + 0x20 + 12)
        self.assertEqual(self.state["user_objects"], table_after_first)
        self.assertEqual(len(self.state["user_objects"]), 1)
        self.assertEqual([call["result"] for call in self.state["api_calls"]],
                         [first_handle, first_handle])

    def test_cursor_unknown_arguments_and_missing_table_are_unsupported(self) -> None:
        esp = STACK_BASE + 0x100
        cases = (
            ("module_instance", IMAGE_BASE, OCR_NORMAL_RESOURCE_ID, {}),
            ("unknown_system_id", 0, OCR_NORMAL_RESOURCE_ID + 1, {}),
            ("table_missing", 0, OCR_NORMAL_RESOURCE_ID, {"remove_table": True}),
        )
        for name, instance, system_id, changes in cases:
            with self.subTest(case=name):
                self.state["user_objects"] = { }
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.state["tls_current_teb"] = 0
                self.write_frame(esp=esp, instance=instance,
                                 icon_name=system_id)
                if changes.get("remove_table"):
                    self.state.pop("user_objects")
                self.engine.mem_write(
                    TEB_BASE + LAST_ERROR_OFFSET,
                    struct.pack("<I", LAST_ERROR_SENTINEL))
                registers_before = self.registers()
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                teb_before = bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE))
                state_before = dict(self.state)

                self.assertFalse(self.call_import(row=self.cursor_row))

                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE)),
                                 teb_before)
                self.assertEqual(self.state, state_before)

    def test_full_user_object_table_rejects_unrepresented_cursor_atomically(self) -> None:
        table = {}
        for slot in range(USER_OBJECT_CAPACITY):
            handle = USER_OBJECT_HANDLE_BASE + slot
            table[handle] = {
                "handle": handle,
                "kind": "ICON",
                "origin": "SYSTEM_SHARED",
                "system_id": 1 + slot,
                "module": 0,
                "shared": True,
            }
        self.state["user_objects"] = table
        self.state["tls_current_teb"] = 0
        esp = STACK_BASE + 0x100
        self.write_frame(esp=esp, instance=0,
                         icon_name=OCR_NORMAL_RESOURCE_ID)
        registers_before = self.registers()
        stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
        state_before = dict(self.state)

        self.assertFalse(self.call_import(row=self.cursor_row))

        self.assertEqual(self.registers(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                         stack_before)
        self.assertEqual(self.state, state_before)

    def test_full_table_still_deduplicates_existing_shared_cursor(self) -> None:
        table = {}
        matching_handle = USER_OBJECT_HANDLE_BASE + USER_OBJECT_CAPACITY - 1
        for slot in range(USER_OBJECT_CAPACITY):
            handle = USER_OBJECT_HANDLE_BASE + slot
            if slot == USER_OBJECT_CAPACITY - 1:
                table[handle] = {
                    "handle": handle,
                    "kind": "CURSOR",
                    "origin": "SYSTEM_SHARED",
                    "system_id": OCR_NORMAL_RESOURCE_ID,
                    "module": 0,
                    "shared": True,
                }
            else:
                table[handle] = {
                    "handle": handle,
                    "kind": "ICON",
                    "origin": "SYSTEM_SHARED",
                    "system_id": 1 + slot,
                    "module": 0,
                    "shared": True,
                }
        self.state["user_objects"] = table
        self.state["tls_current_teb"] = 0
        self.write_frame(instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)

        self.assertTrue(self.call_import(row=self.cursor_row))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         matching_handle)
        self.assertEqual(len(self.state["user_objects"]), USER_OBJECT_CAPACITY)
        self.assertEqual(self.state["api_calls"][0]["result"], matching_handle)

    def test_valid_pe_entry_uses_the_next_virtual_slot(self) -> None:
        first_handle = USER_OBJECT_HANDLE_BASE
        pe_entry = {
            "handle": first_handle,
            "kind": "ICON",
            "origin": "PE_IMAGE",
            "system_id": 42,
            "module": IMAGE_BASE,
            "shared": 0,
        }
        self.state["user_objects"] = {first_handle: pe_entry}
        self.state["tls_current_teb"] = 0
        self.write_frame(instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)

        self.assertTrue(self.call_import(row=self.cursor_row))

        cursor_handle = USER_OBJECT_HANDLE_BASE + 1
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         cursor_handle)
        self.assertEqual(self.state["user_objects"][first_handle], pe_entry)
        self.assertEqual(self.state["user_objects"][cursor_handle]["kind"],
                         "CURSOR")

    def test_integer_shared_flag_normalizes_for_fulltype_dedup(self) -> None:
        handle = USER_OBJECT_HANDLE_BASE
        descriptor = {
            "handle": handle,
            "kind": "CURSOR",
            "origin": "SYSTEM_SHARED",
            "system_id": OCR_NORMAL_RESOURCE_ID,
            "module": 0,
            "shared": 1,
        }
        self.state["user_objects"] = {handle: descriptor}
        self.state["tls_current_teb"] = 0
        table_before = deepcopy(self.state["user_objects"])
        self.write_frame(instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)

        self.assertTrue(self.call_import(row=self.cursor_row))

        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), handle)
        self.assertEqual(self.state["user_objects"], table_before)

    def test_malformed_user_object_descriptors_reject_atomically(self) -> None:
        handle = USER_OBJECT_HANDLE_BASE
        baseline = {
            "handle": handle,
            "kind": "ICON",
            "origin": "PE_IMAGE",
            "system_id": 42,
            "module": IMAGE_BASE,
            "shared": False,
        }
        cases = (
            ("invalid_kind", {"kind": "BRUSH"}),
            ("missing_handle", {"handle": None}),
            ("mismatched_handle", {"handle": handle + 1}),
            ("missing_module", {"module": None}),
            ("pe_module_zero", {"module": 0}),
            ("system_module_nonzero", {
                "origin": "SYSTEM_SHARED", "module": IMAGE_BASE,
                "system_id": OCR_NORMAL_RESOURCE_ID, "shared": True,
            }),
            ("system_not_shared", {
                "origin": "SYSTEM_SHARED", "module": 0,
                "system_id": OCR_NORMAL_RESOURCE_ID, "shared": 0,
            }),
            ("missing_shared", {"shared": None}),
            ("shared_out_of_range", {"shared": 2}),
            ("shared_wrong_type", {"shared": "true"}),
            ("invalid_origin", {"origin": "HOST"}),
            ("invalid_system_id", {"system_id": -1}),
        )
        esp = STACK_BASE + 0x100
        for name, changes in cases:
            with self.subTest(case=name):
                entry = dict(baseline)
                for field, value in changes.items():
                    if field == "handle" and value is None:
                        entry.pop("handle")
                    elif value is None:
                        entry.pop(field)
                    else:
                        entry[field] = value
                table = {handle: entry}
                self.state["user_objects"] = table
                self.state["tls_current_teb"] = 0
                self.state["api_calls"] = []
                self.state["resume"] = False
                self.state["status"] = None
                self.write_frame(esp=esp, instance=0,
                                 icon_name=OCR_NORMAL_RESOURCE_ID)
                self.engine.mem_write(
                    TEB_BASE + LAST_ERROR_OFFSET,
                    struct.pack("<I", LAST_ERROR_SENTINEL))
                table_before = deepcopy(table)
                stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
                teb_before = bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE))
                registers_before = self.registers()
                state_before = dict(self.state)

                self.assertFalse(self.call_import(row=self.cursor_row))

                self.assertEqual(self.registers(), registers_before)
                self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                                 stack_before)
                self.assertEqual(bytes(self.engine.mem_read(TEB_BASE, PAGE_SIZE)),
                                 teb_before)
                self.assertEqual(self.state["user_objects"], table_before)
                self.assertEqual(self.state, state_before)

    def test_out_of_range_user_object_slot_rejects_atomically(self) -> None:
        invalid_handle = USER_OBJECT_HANDLE_BASE + USER_OBJECT_CAPACITY
        self.state["user_objects"] = {
            invalid_handle: {
                "handle": invalid_handle,
                "kind": "ICON",
                "origin": "PE_IMAGE",
                "system_id": 42,
                "module": IMAGE_BASE,
                "shared": False,
            },
        }
        self.state["tls_current_teb"] = 0
        self.write_frame(instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)
        table_before = deepcopy(self.state["user_objects"])
        state_before = dict(self.state)
        registers_before = self.registers()
        stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))

        self.assertFalse(self.call_import(row=self.cursor_row))

        self.assertEqual(self.registers(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                         stack_before)
        self.assertEqual(self.state["user_objects"], table_before)
        self.assertEqual(self.state, state_before)

    def test_duplicate_matching_shared_cursor_descriptors_reject_atomically(self) -> None:
        table = {}
        for slot in range(2):
            handle = USER_OBJECT_HANDLE_BASE + slot
            table[handle] = {
                "handle": handle,
                "kind": "CURSOR",
                "origin": "SYSTEM_SHARED",
                "system_id": OCR_NORMAL_RESOURCE_ID,
                "module": 0,
                "shared": True,
            }
        self.state["user_objects"] = table
        self.state["tls_current_teb"] = 0
        self.state["api_calls"] = []
        self.write_frame(instance=0, icon_name=OCR_NORMAL_RESOURCE_ID)
        table_before = deepcopy(table)
        registers_before = self.registers()
        stack_before = bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE))
        state_before = dict(self.state)

        self.assertFalse(self.call_import(row=self.cursor_row))

        self.assertEqual(self.registers(), registers_before)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, PAGE_SIZE)),
                         stack_before)
        self.assertEqual(self.state["user_objects"], table_before)
        self.assertEqual(self.state, state_before)


if __name__ == "__main__":
    unittest.main()
