#!/usr/bin/env python3
"""Synthetic-memory contract tests for the private x86 startup oracle."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
PRIVATE_DEPS = ROOT / "out" / "private-deps"
if PRIVATE_DEPS.is_dir():
    sys.path.insert(0, str(PRIVATE_DEPS))

import unicorn
from unicorn import x86_const

from startup_oracle import (
    CRITICAL_SECTION_MAX_COUNT,
    CRITICAL_SECTION_SIZE,
    EFLAGS_MASK,
    IMPORT_BASE,
    TEB_BASE,
    TEB_SIZE,
    _critical_section_import,
)


STRUCT_BASE = 0x00300000
PAGE_SIZE = 0x1000
STACK_BASE = 0x00500000
RETURN_ADDRESS = 0x00123456
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
LAST_ERROR_SENTINEL = 0x76543210
THREAD_ID = 1


class CriticalSectionOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STRUCT_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, TEB_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_write(TEB_BASE + 0x24, struct.pack("<I", THREAD_ID))
        self.engine.mem_write(TEB_BASE + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.mapped_ranges = [
            (STRUCT_BASE, STRUCT_BASE + PAGE_SIZE),
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + TEB_SIZE),
        ]
        self.state = {
            "last_ip": 0x00101010,
            "api_calls": [],
            "critical_sections": {},
            "resume": False,
            "status": None,
        }

    def call_api(self, name: str, address: int, *, esp: int = STACK_BASE,
                 eax: int = EAX_SENTINEL, flags: int = FLAGS_SENTINEL) -> dict:
        self.engine.mem_write(esp, struct.pack("<II", RETURN_ADDRESS, address))
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, eax)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, flags)
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        EFLAGS_MASK)
        row = {"library": "KERNEL32.dll", "name": name, "index": 7}
        handled = _critical_section_import(
            self.engine, x86_const, row, self.mapped_ranges, self.state)
        return {
            "handled": handled,
            "esp_before": esp,
            "eax_before": eax,
            "flags_before": flags_before,
            "esp_after": self.engine.reg_read(x86_const.UC_X86_REG_ESP),
            "eip_after": self.engine.reg_read(x86_const.UC_X86_REG_EIP),
            "eax_after": self.engine.reg_read(x86_const.UC_X86_REG_EAX),
            "flags_after": (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                            EFLAGS_MASK),
        }

    def assert_successful_stdcall(self, result: dict, expected_eax: int) -> None:
        self.assertTrue(result["handled"])
        self.assertEqual(result["esp_after"], result["esp_before"] + 8)
        self.assertEqual(result["eip_after"], RETURN_ADDRESS)
        self.assertEqual(result["eax_after"], expected_eax)
        self.assertEqual(result["flags_after"], result["flags_before"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )

    def seed_foreign_owner(self, address: int) -> bytes:
        section = self.state["critical_sections"][address]
        section.update(lock_count=0, recursion_count=1, owning_thread=2)
        self.engine.mem_write(address, struct.pack("<6I", 0, 0, 1, 2, 0, 0))
        return bytes(self.engine.mem_read(address, CRITICAL_SECTION_SIZE))

    def test_init_recursive_acquire_release_and_abi_preservation(self) -> None:
        address = STRUCT_BASE + 0x80
        self.assert_successful_stdcall(
            self.call_api("InitializeCriticalSection", address), EAX_SENTINEL)
        self.assertEqual(
            struct.unpack("<6I", self.engine.mem_read(address, 24)),
            (0, 0xFFFFFFFF, 0, 0, 0, 0),
        )
        self.assertEqual(self.state["critical_sections"][address], {
            "lock_count": 0xFFFFFFFF,
            "recursion_count": 0,
            "owning_thread": 0,
        })

        self.assert_successful_stdcall(
            self.call_api("TryEnterCriticalSection", address), 1)
        self.assert_successful_stdcall(
            self.call_api("EnterCriticalSection", address), EAX_SENTINEL)
        self.assertEqual(self.state["critical_sections"][address], {
            "lock_count": 1,
            "recursion_count": 2,
            "owning_thread": THREAD_ID,
        })
        self.assertEqual(
            struct.unpack("<6I", self.engine.mem_read(address, 24)),
            (0, 1, 2, THREAD_ID, 0, 0),
        )

        self.assert_successful_stdcall(
            self.call_api("LeaveCriticalSection", address), EAX_SENTINEL)
        self.assertEqual(self.state["critical_sections"][address]["recursion_count"], 1)
        self.assert_successful_stdcall(
            self.call_api("LeaveCriticalSection", address), EAX_SENTINEL)
        self.assertEqual(self.state["critical_sections"][address], {
            "lock_count": 0xFFFFFFFF,
            "recursion_count": 0,
            "owning_thread": 0,
        })

    def test_tryenter_foreign_owner_returns_false_without_mutation(self) -> None:
        address = STRUCT_BASE + 0x100
        self.assert_successful_stdcall(
            self.call_api("InitializeCriticalSection", address), EAX_SENTINEL)
        before = self.seed_foreign_owner(address)
        metadata_before = dict(self.state["critical_sections"][address])

        result = self.call_api("TryEnterCriticalSection", address)

        self.assert_successful_stdcall(result, 0)
        self.assertEqual(bytes(self.engine.mem_read(address, 24)), before)
        self.assertEqual(self.state["critical_sections"][address], metadata_before)
        self.assertEqual(self.state["api_calls"][-1]["outcome"], "contended")

    def test_enter_contention_stops_and_retains_call_frame(self) -> None:
        address = STRUCT_BASE + 0x180
        self.assert_successful_stdcall(
            self.call_api("InitializeCriticalSection", address), EAX_SENTINEL)
        before = self.seed_foreign_owner(address)
        self.engine.mem_write(STACK_BASE, struct.pack("<II", RETURN_ADDRESS, address))
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, STACK_BASE)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 7)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        frame_before = bytes(self.engine.mem_read(STACK_BASE, 8))
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        EFLAGS_MASK)

        handled = _critical_section_import(
            self.engine, x86_const,
            {"library": "KERNEL32.dll", "name": "EnterCriticalSection", "index": 7},
            self.mapped_ranges, self.state)

        self.assertFalse(handled)
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(
            self.state["api_state_fault"]["reason"],
            "critical_section_contention_unschedulable",
        )
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), STACK_BASE)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), IMPORT_BASE + 7)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), EAX_SENTINEL)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & EFLAGS_MASK,
            flags_before,
        )
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame_before)
        self.assertEqual(bytes(self.engine.mem_read(address, 24)), before)

    def test_leave_delete_ownership_and_delete_zeroing(self) -> None:
        address = STRUCT_BASE + 0x200
        self.assert_successful_stdcall(
            self.call_api("InitializeCriticalSection", address), EAX_SENTINEL)

        unowned_leave = self.call_api("LeaveCriticalSection", address)
        self.assertFalse(unowned_leave["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_leave_not_owned")

        self.state["status"] = None
        self.assert_successful_stdcall(
            self.call_api("EnterCriticalSection", address), EAX_SENTINEL)
        owned_bytes = bytes(self.engine.mem_read(address, 24))
        self.engine.mem_write(TEB_BASE + 0x24, struct.pack("<I", THREAD_ID + 1))
        foreign_leave = self.call_api("LeaveCriticalSection", address)
        self.assertFalse(foreign_leave["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_leave_not_owned")
        self.assertEqual(bytes(self.engine.mem_read(address, 24)), owned_bytes)
        self.engine.mem_write(TEB_BASE + 0x24, struct.pack("<I", THREAD_ID))
        self.state["status"] = None
        owned_delete = self.call_api("DeleteCriticalSection", address)
        self.assertFalse(owned_delete["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_delete_owned")

        self.state["status"] = None
        self.assert_successful_stdcall(
            self.call_api("LeaveCriticalSection", address), EAX_SENTINEL)
        self.mapped_ranges.remove((TEB_BASE, TEB_BASE + TEB_SIZE))
        self.assert_successful_stdcall(
            self.call_api("DeleteCriticalSection", address), EAX_SENTINEL)
        self.assertNotIn(address, self.state["critical_sections"])
        self.assertEqual(bytes(self.engine.mem_read(address, 24)), bytes(24))

    def test_duplicate_overlap_and_capacity_are_api_state_stops(self) -> None:
        address = STRUCT_BASE + 0x280
        self.assert_successful_stdcall(
            self.call_api("InitializeCriticalSection", address), EAX_SENTINEL)
        duplicate = self.call_api("InitializeCriticalSection", address)
        self.assertFalse(duplicate["handled"])
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_already_initialized")

        self.state["status"] = None
        overlap = self.call_api("InitializeCriticalSection", address + 8)
        self.assertFalse(overlap["handled"])
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_overlap")

        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STRUCT_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, TEB_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_write(TEB_BASE + 0x24, struct.pack("<I", THREAD_ID))
        self.engine.mem_write(TEB_BASE + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.state = {
            "last_ip": 0x00101010,
            "api_calls": [],
            "critical_sections": {},
            "resume": False,
            "status": None,
        }
        for index in range(CRITICAL_SECTION_MAX_COUNT):
            result = self.call_api(
                "InitializeCriticalSection",
                STRUCT_BASE + 0x400 + index * CRITICAL_SECTION_SIZE,
            )
            self.assertTrue(result["handled"])
        over_cap = STRUCT_BASE + 0x400 + CRITICAL_SECTION_MAX_COUNT * CRITICAL_SECTION_SIZE
        memory_before = bytes(self.engine.mem_read(over_cap, CRITICAL_SECTION_SIZE))
        result = self.call_api("InitializeCriticalSection", over_cap)
        self.assertFalse(result["handled"])
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "critical_section_limit")
        self.assertEqual(self.state["api_state_fault"]["critical_section_count"],
                         CRITICAL_SECTION_MAX_COUNT)
        self.assertEqual(bytes(self.engine.mem_read(over_cap, 24)), memory_before)

    def test_unmapped_and_cross_range_objects_stop_as_memory_faults(self) -> None:
        for address in (STRUCT_BASE + PAGE_SIZE - 8, STRUCT_BASE + PAGE_SIZE):
            with self.subTest(address=hex(address)):
                result = self.call_api("InitializeCriticalSection", address)
                self.assertFalse(result["handled"])
                self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
                self.assertEqual(self.state["memory_fault"], {
                    "access": "read_write",
                    "address": address,
                    "size": CRITICAL_SECTION_SIZE,
                })
                self.assertEqual(self.state["critical_sections"], {})


if __name__ == "__main__":
    unittest.main()
