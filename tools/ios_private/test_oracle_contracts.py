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
    ERROR_NOT_ENOUGH_MEMORY,
    EFLAGS_MASK,
    HEAP_ALLOC_SUPPORTED_FLAGS,
    HEAP_BASE,
    HEAP_GRANULE,
    HEAP_HEADER_SIZE,
    HEAP_MAX_BLOCKS,
    HEAP_MAX_COUNT,
    HEAP_SUPPORTED_FLAGS,
    IMPORT_BASE,
    TLS_MAX_THREAD_COUNT,
    TLS_SLOT_BYTES,
    TLS_SLOT_COUNT,
    TEB_THREAD_ID_OFFSET,
    TEB_TLS_SLOTS_OFFSET,
    TEB_BASE,
    TEB_SIZE,
    _critical_section_import,
    _get_current_thread_id,
    _heap_alloc,
    _heap_create,
    _tls_import,
)


STRUCT_BASE = 0x00300000
PAGE_SIZE = 0x1000
STACK_BASE = 0x00500000
RETURN_ADDRESS = 0x00123456
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
LAST_ERROR_SENTINEL = 0x76543210
THREAD_ID = 1
TLS_TEB_2 = 0x00D00000
TLS_VALUE_BASE = 0x00600000


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


class TlsOracleTests(unittest.TestCase):
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
            "tls_allocated_bitmap": 0,
            "tls_slot_count": 0,
            "tls_threads": {TEB_BASE: THREAD_ID},
            "tls_current_teb": TEB_BASE,
            "resume": False,
            "status": None,
        }

    def call_api(self, name: str, *arguments: int,
                 esp: int = STACK_BASE) -> dict:
        frame = struct.pack("<" + "I" * (len(arguments) + 1),
                            RETURN_ADDRESS, *arguments)
        self.engine.mem_write(esp, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 11)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        EFLAGS_MASK)
        eax_before = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        row = {"library": "KERNEL32.dll", "name": name, "index": 11}
        handled = _tls_import(self.engine, x86_const, unicorn,
                              row, self.mapped_ranges, self.state)
        return {
            "handled": handled,
            "esp_before": esp,
            "frame_before": frame,
            "eax_before": eax_before,
            "flags_before": flags_before,
            "esp_after": self.engine.reg_read(x86_const.UC_X86_REG_ESP),
            "eip_after": self.engine.reg_read(x86_const.UC_X86_REG_EIP),
            "eax_after": self.engine.reg_read(x86_const.UC_X86_REG_EAX),
            "flags_after": (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                            EFLAGS_MASK),
        }

    def assert_successful_stdcall(self, result: dict, argc: int,
                                  expected_eax: int) -> None:
        self.assertTrue(result["handled"])
        self.assertEqual(result["esp_after"],
                         result["esp_before"] + 4 * (argc + 1))
        self.assertEqual(result["eip_after"], RETURN_ADDRESS)
        self.assertEqual(result["eax_after"], expected_eax)
        self.assertEqual(result["flags_after"], result["flags_before"])

    def assert_stopped_without_mutation(self, result: dict, expected_status: str,
                                        *, expected_reason: str | None = None,
                                        snapshot: dict | None = None) -> None:
        self.assertFalse(result["handled"])
        self.assertEqual(self.state["status"], expected_status)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         result["esp_before"])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 11)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         result["eax_before"])
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & EFLAGS_MASK,
            result["flags_before"],
        )
        self.assertEqual(bytes(self.engine.mem_read(result["esp_before"],
                                                    len(result["frame_before"]))),
                         result["frame_before"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )
        if expected_reason is not None:
            self.assertEqual(self.state["api_state_fault"]["reason"],
                             expected_reason)
        if snapshot is not None:
            for key, value in snapshot.items():
                self.assertEqual(self.state[key], value)

    def allocate(self) -> int:
        result = self.call_api("TlsAlloc")
        self.assertTrue(result["handled"])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         STACK_BASE + 4)
        return int(result["eax_after"])

    def map_second_teb(self, thread_id: int = 2) -> None:
        if not any(start == TLS_TEB_2 for start, _ in self.mapped_ranges):
            self.engine.mem_map(TLS_TEB_2, TEB_SIZE, unicorn.UC_PROT_ALL)
            self.mapped_ranges.append((TLS_TEB_2, TLS_TEB_2 + TEB_SIZE))
        self.engine.mem_write(TLS_TEB_2 + 0x24, struct.pack("<I", thread_id))
        self.engine.mem_write(TLS_TEB_2 + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))

    def test_alloc_set_get_free_reuse_and_last_error_contract(self) -> None:
        index = self.allocate()
        self.assertEqual(index, 0)
        self.assertEqual(self.state["tls_slot_count"], 1)
        self.assertEqual(self.state["tls_allocated_bitmap"], 1)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )

        for value in (0, 0xFFFFFFFF, 0x80000000, 0x12345678):
            with self.subTest(value=hex(value)):
                self.engine.mem_write(TEB_BASE + 0x34,
                                      struct.pack("<I", LAST_ERROR_SENTINEL))
                result = self.call_api("TlsSetValue", index, value)
                self.assert_successful_stdcall(result, 2, 1)
                self.assertEqual(
                    struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
                    LAST_ERROR_SENTINEL,
                )
                result = self.call_api("TlsGetValue", index)
                self.assert_successful_stdcall(result, 1, value)
                self.assertEqual(
                    struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
                    0,
                )

        # A nonzero value can be a raw pointer-shaped DWORD; the oracle never
        # dereferences or owns that address.
        raw_pointer = 0xDEADC0DE
        self.assert_successful_stdcall(
            self.call_api("TlsSetValue", index, raw_pointer), 2, 1)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(
                TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * index, 4))[0],
            raw_pointer,
        )

        result = self.call_api("TlsFree", index)
        self.assert_successful_stdcall(result, 1, 1)
        self.assertEqual(self.state["tls_slot_count"], 0)
        self.assertEqual(self.state["tls_allocated_bitmap"], 0)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(
                TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * index, 4))[0],
            0,
        )
        reused = self.allocate()
        self.assertEqual(reused, index)
        result = self.call_api("TlsGetValue", reused)
        self.assert_successful_stdcall(result, 1, 0)

    def test_per_thread_values_are_isolated_and_new_teb_starts_zero(self) -> None:
        index = self.allocate()
        self.assert_successful_stdcall(
            self.call_api("TlsSetValue", index, 0x11112222), 2, 1)
        self.map_second_teb()
        self.state["tls_current_teb"] = TLS_TEB_2

        result = self.call_api("TlsGetValue", index)
        self.assert_successful_stdcall(result, 1, 0)
        self.assertEqual(self.state["tls_threads"][TLS_TEB_2], 2)
        self.assertEqual(len(self.state["tls_threads"]), 2)
        self.assertEqual(
            bytes(self.engine.mem_read(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET,
                                       TLS_SLOT_BYTES)),
            bytes(TLS_SLOT_BYTES),
        )

        self.assert_successful_stdcall(
            self.call_api("TlsSetValue", index, 0x33334444), 2, 1)
        self.state["tls_current_teb"] = TEB_BASE
        self.assert_successful_stdcall(
            self.call_api("TlsGetValue", index), 1, 0x11112222)
        self.state["tls_current_teb"] = TLS_TEB_2
        self.assert_successful_stdcall(
            self.call_api("TlsGetValue", index), 1, 0x33334444)

    def test_free_and_alloc_reset_all_registered_threads_transactionally(self) -> None:
        index = self.allocate()
        self.map_second_teb()
        self.state["tls_threads"][TLS_TEB_2] = 2
        self.engine.mem_write(TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * index,
                              struct.pack("<I", 0x11111111))
        self.engine.mem_write(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET + 4 * index,
                              struct.pack("<I", 0x22222222))
        selected_second = TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET + 4 * index
        original_range = (TLS_TEB_2, TLS_TEB_2 + TEB_SIZE)
        self.mapped_ranges.remove(original_range)
        self.mapped_ranges.append((TLS_TEB_2, selected_second))
        slots_before = bytes(self.engine.mem_read(
            TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * index, 4))
        second_before = bytes(self.engine.mem_read(selected_second, 4))
        model_before = {"tls_allocated_bitmap": self.state["tls_allocated_bitmap"],
                        "tls_slot_count": self.state["tls_slot_count"],
                        "tls_threads": dict(self.state["tls_threads"])}

        result = self.call_api("TlsFree", index)
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_MEMORY", snapshot=model_before)
        self.assertEqual(bytes(self.engine.mem_read(
            TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * index, 4)), slots_before)
        self.assertEqual(bytes(self.engine.mem_read(selected_second, 4)),
                         second_before)

        # Allocation has the same all-thread preflight before resetting values
        # and publishing the new key.
        self.state["status"] = None
        self.mapped_ranges.remove((TLS_TEB_2, selected_second))
        self.mapped_ranges.append(original_range)
        self.assert_successful_stdcall(
            self.call_api("TlsFree", index), 1, 1)
        new_index = self.allocate()
        self.assertEqual(new_index, index)
        self.engine.mem_write(TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * new_index,
                              struct.pack("<I", 0xAAAAAAAA))
        self.engine.mem_write(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET + 4 * new_index,
                              struct.pack("<I", 0xBBBBBBBB))
        self.mapped_ranges.remove(original_range)
        self.mapped_ranges.append((TLS_TEB_2,
                                   TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET + 4 * new_index))
        model_before = {"tls_allocated_bitmap": self.state["tls_allocated_bitmap"],
                        "tls_slot_count": self.state["tls_slot_count"],
                        "tls_threads": dict(self.state["tls_threads"])}
        result = self.call_api("TlsAlloc")
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_MEMORY", snapshot=model_before)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(
                TEB_BASE + TEB_TLS_SLOTS_OFFSET + 4 * new_index, 4))[0],
            0xAAAAAAAA,
        )

    def test_fresh_thread_full_vector_failure_does_not_register_or_zero(self) -> None:
        index = self.allocate()
        self.map_second_teb()
        self.engine.mem_write(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET,
                              bytes([0xA5]) * TLS_SLOT_BYTES)
        self.state["tls_current_teb"] = TLS_TEB_2
        self.mapped_ranges.remove((TLS_TEB_2, TLS_TEB_2 + TEB_SIZE))
        self.mapped_ranges.append((TLS_TEB_2,
                                   TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET))
        slots_before = bytes(self.engine.mem_read(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET,
                                                  TLS_SLOT_BYTES))
        model_before = {"tls_allocated_bitmap": self.state["tls_allocated_bitmap"],
                        "tls_slot_count": self.state["tls_slot_count"],
                        "tls_threads": dict(self.state["tls_threads"])}

        result = self.call_api("TlsGetValue", index)

        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_MEMORY", snapshot=model_before)
        self.assertEqual(bytes(self.engine.mem_read(
            TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET, TLS_SLOT_BYTES)), slots_before)

    def test_invalid_keys_precede_thread_id_read_and_leave_state_unchanged(self) -> None:
        # LastError remains accessible, but the current ID is zero. Native
        # guest_tls_apply validates a non-ALLOC key before reading the ID.
        self.engine.mem_write(TEB_BASE + 0x24, struct.pack("<I", 0))
        snapshot = {"tls_allocated_bitmap": self.state["tls_allocated_bitmap"],
                    "tls_slot_count": self.state["tls_slot_count"],
                    "tls_threads": dict(self.state["tls_threads"])}
        result = self.call_api("TlsGetValue", 0)
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_API_STATE",
            expected_reason="tls_index_not_allocated", snapshot=snapshot)

        self.state["status"] = None
        self.engine.mem_write(TEB_BASE + 0x24,
                              struct.pack("<I", THREAD_ID))
        index = self.allocate()
        result = self.call_api("TlsFree", 0xFFFFFFFF)
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_API_STATE",
            expected_reason="tls_index_out_of_range",
            snapshot={"tls_allocated_bitmap": 1,
                      "tls_slot_count": 1,
                      "tls_threads": {TEB_BASE: THREAD_ID}})
        self.assertEqual(index, 0)

    def test_duplicate_identity_overlap_and_thread_cap_policies(self) -> None:
        key = self.allocate()
        self.map_second_teb(thread_id=THREAD_ID)
        self.state["tls_current_teb"] = TLS_TEB_2
        result = self.call_api("TlsGetValue", key)
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_API_STATE", expected_reason="tls_thread_id_alias",
            snapshot={"tls_allocated_bitmap": 1,
                      "tls_slot_count": 1,
                      "tls_threads": {TEB_BASE: THREAD_ID}})

        self.state["status"] = None
        # The overlapping TEB lies inside the mapped main TEB and has its own
        # nonzero ID, so rejection is specifically the 0x1000 footprint rule.
        overlap_teb = TEB_BASE + 0x800
        self.engine.mem_write(overlap_teb + 0x24, struct.pack("<I", 2))
        self.engine.mem_write(overlap_teb + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.state["tls_current_teb"] = overlap_teb
        result = self.call_api("TlsAlloc")
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_API_STATE", expected_reason="tls_thread_teb_overlap",
            snapshot={"tls_allocated_bitmap": 1,
                      "tls_slot_count": 1,
                      "tls_threads": {TEB_BASE: THREAD_ID}})

        self.state["status"] = None
        self.state["tls_current_teb"] = TEB_BASE
        threads = {TEB_BASE: THREAD_ID}
        for thread_index in range(1, TLS_MAX_THREAD_COUNT):
            threads[0x30000000 + thread_index * 0x2000] = thread_index + 1
        self.state["tls_threads"] = threads
        self.map_second_teb(thread_id=TLS_MAX_THREAD_COUNT + 1)
        self.state["tls_current_teb"] = TLS_TEB_2
        # The bounded runner policy maps ENOSPC on Alloc to TLS_OUT_OF_INDEXES
        # even when the bound is guest-thread registration, without recording
        # that TEB or altering its initially nonzero vector.
        self.engine.mem_write(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET,
                              bytes([0x5A]) * TLS_SLOT_BYTES)
        slots_before = bytes(self.engine.mem_read(TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET,
                                                  TLS_SLOT_BYTES))
        result = self.call_api("TlsAlloc")
        self.assert_successful_stdcall(result, 0, 0xFFFFFFFF)
        self.assertEqual(self.state["api_calls"][-1]["exhaustion"],
                         "thread_limit")
        self.assertEqual(self.state["tls_slot_count"], 1)
        self.assertEqual(len(self.state["tls_threads"]), TLS_MAX_THREAD_COUNT)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TLS_TEB_2 + 0x34, 4))[0],
            ERROR_NOT_ENOUGH_MEMORY,
        )
        self.assertEqual(bytes(self.engine.mem_read(
            TLS_TEB_2 + TEB_TLS_SLOTS_OFFSET, TLS_SLOT_BYTES)), slots_before)

        self.state["status"] = None
        self.engine.mem_write(TLS_TEB_2 + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        result = self.call_api("TlsGetValue", key)
        self.assert_stopped_without_mutation(
            result, "GUEST_STOP_API_STATE", expected_reason="tls_thread_limit",
            snapshot={"tls_allocated_bitmap": 1,
                      "tls_slot_count": 1,
                      "tls_threads": threads})

    def test_key_exhaustion_returns_tls_out_of_indexes_without_mutation(self) -> None:
        self.state["tls_allocated_bitmap"] = (1 << TLS_SLOT_COUNT) - 1
        self.state["tls_slot_count"] = TLS_SLOT_COUNT
        slots_before = bytes(self.engine.mem_read(
            TEB_BASE + TEB_TLS_SLOTS_OFFSET, TLS_SLOT_BYTES))
        result = self.call_api("TlsAlloc")
        self.assert_successful_stdcall(result, 0, 0xFFFFFFFF)
        self.assertEqual(self.state["tls_slot_count"], TLS_SLOT_COUNT)
        self.assertEqual(self.state["tls_allocated_bitmap"],
                         (1 << TLS_SLOT_COUNT) - 1)
        self.assertEqual(bytes(self.engine.mem_read(
            TEB_BASE + TEB_TLS_SLOTS_OFFSET, TLS_SLOT_BYTES)), slots_before)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            ERROR_NOT_ENOUGH_MEMORY,
        )

    def test_stack_and_last_error_preflight_fail_before_tls_state_changes(self) -> None:
        snapshot = {"tls_allocated_bitmap": self.state["tls_allocated_bitmap"],
                    "tls_slot_count": self.state["tls_slot_count"],
                    "tls_threads": dict(self.state["tls_threads"])}
        bad_esp = STACK_BASE + PAGE_SIZE
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, bad_esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 11)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        self.assertFalse(_tls_import(
            self.engine, x86_const, unicorn,
            {"library": "KERNEL32.dll", "name": "TlsAlloc", "index": 11},
            self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), bad_esp)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 11)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         EAX_SENTINEL)
        self.assertEqual(self.state["tls_allocated_bitmap"],
                         snapshot["tls_allocated_bitmap"])
        self.assertEqual(self.state["tls_slot_count"], snapshot["tls_slot_count"])
        self.assertEqual(self.state["tls_threads"], snapshot["tls_threads"])

        self.state["status"] = None
        self.engine.mem_protect(TEB_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        result = self.call_api("TlsAlloc")
        self.assertFalse(result["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["tls_allocated_bitmap"], 0)
        self.assertEqual(self.state["tls_slot_count"], 0)


class CurrentThreadIdOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, TEB_SIZE, unicorn.UC_PROT_ALL)
        self.thread_id = 0x2468ACE0
        self.engine.mem_write(TEB_BASE + TEB_THREAD_ID_OFFSET,
                              struct.pack("<I", self.thread_id))
        self.engine.mem_write(TEB_BASE + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + TEB_SIZE),
        ]
        self.state = {
            "last_ip": 0x00104050,
            "api_calls": [],
            "tls_current_teb": TEB_BASE,
            "resume": False,
            "status": None,
        }
        self.other_registers = {
            x86_const.UC_X86_REG_ECX: 0x11111111,
            x86_const.UC_X86_REG_EDX: 0x22222222,
            x86_const.UC_X86_REG_EBX: 0x33333333,
            x86_const.UC_X86_REG_EBP: 0x44444444,
            x86_const.UC_X86_REG_ESI: 0x55555555,
            x86_const.UC_X86_REG_EDI: 0x66666666,
        }

    def call_api(self, *, write_frame: bool = True,
                 teb: int | None = None) -> dict:
        if teb is not None:
            self.state["tls_current_teb"] = teb
        frame = struct.pack("<I", RETURN_ADDRESS)
        if write_frame:
            self.engine.mem_write(STACK_BASE, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, STACK_BASE)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 17)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for register, value in self.other_registers.items():
            self.engine.reg_write(register, value)
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        EFLAGS_MASK)
        row = {"library": "KERNEL32.dll", "name": "GetCurrentThreadId",
               "index": 17}
        handled = _get_current_thread_id(
            self.engine, x86_const, unicorn, row,
            self.mapped_ranges, self.state)
        return {
            "handled": handled,
            "frame": frame,
            "flags_before": flags_before,
            "eax_after": self.engine.reg_read(x86_const.UC_X86_REG_EAX),
            "esp_after": self.engine.reg_read(x86_const.UC_X86_REG_ESP),
            "eip_after": self.engine.reg_read(x86_const.UC_X86_REG_EIP),
            "flags_after": (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                            EFLAGS_MASK),
        }

    def assert_preserved_registers(self) -> None:
        for register, value in self.other_registers.items():
            self.assertEqual(self.engine.reg_read(register), value)

    def test_success_returns_teb_id_and_preserves_nonresult_state(self) -> None:
        result = self.call_api()
        self.assertTrue(result["handled"])
        self.assertEqual(result["eax_after"], self.thread_id)
        self.assertEqual(result["eip_after"], RETURN_ADDRESS)
        self.assertEqual(result["esp_after"], STACK_BASE + 4)
        self.assertEqual(result["flags_after"], result["flags_before"])
        self.assert_preserved_registers()
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 4)), result["frame"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )
        self.assertEqual(self.state["api_calls"][-1]["arguments"], [])
        self.assertEqual(self.state["api_calls"][-1]["result"], self.thread_id)

    def test_zero_thread_id_is_api_state_and_preserves_call_frame(self) -> None:
        self.engine.mem_write(TEB_BASE + TEB_THREAD_ID_OFFSET,
                              struct.pack("<I", 0))
        result = self.call_api()
        self.assertFalse(result["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["api_state_fault"]["reason"],
                         "current_thread_id_invalid")
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         EAX_SENTINEL)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 17)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         STACK_BASE)
        self.assertEqual(result["flags_after"], result["flags_before"])
        self.assert_preserved_registers()
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 4)), result["frame"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )

    def test_bad_stack_and_teb_ranges_stop_as_memory_faults(self) -> None:
        bad_esp = STACK_BASE + PAGE_SIZE
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, bad_esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 17)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for register, value in self.other_registers.items():
            self.engine.reg_write(register, value)
        self.assertFalse(_get_current_thread_id(
            self.engine, x86_const, unicorn,
            {"library": "KERNEL32.dll", "name": "GetCurrentThreadId", "index": 17},
            self.mapped_ranges, self.state))
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 17)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), bad_esp)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), EAX_SENTINEL)
        self.assertEqual(self.state["memory_fault"]["address"], bad_esp)
        self.assert_preserved_registers()

        self.state["status"] = None
        result = self.call_api(teb=TLS_TEB_2)
        self.assertFalse(result["handled"])
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 17)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), STACK_BASE)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), EAX_SENTINEL)
        self.assertEqual(self.state["memory_fault"]["address"],
                         TLS_TEB_2 + TEB_THREAD_ID_OFFSET)
        self.assert_preserved_registers()


class HeapAllocOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STRUCT_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(TEB_BASE, TEB_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_write(TEB_BASE + 0x34,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.mapped_ranges = [
            (STRUCT_BASE, STRUCT_BASE + PAGE_SIZE),
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (TEB_BASE, TEB_BASE + TEB_SIZE),
        ]
        self.state = {
            "last_ip": 0x00102030,
            "api_calls": [],
            "heaps": {},
            "resume": False,
            "status": None,
        }

    def call_api(self, name: str, *arguments: int) -> dict:
        frame = struct.pack("<IIII", RETURN_ADDRESS, *arguments)
        self.engine.mem_write(STACK_BASE, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, STACK_BASE)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_BASE + 13)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        EFLAGS_MASK)
        eax_before = self.engine.reg_read(x86_const.UC_X86_REG_EAX)
        row = {"library": "KERNEL32.dll", "name": name, "index": 13}
        if name == "HeapCreate":
            handled = _heap_create(self.engine, x86_const, unicorn,
                                   row, self.mapped_ranges, self.state)
        else:
            handled = _heap_alloc(self.engine, x86_const, unicorn,
                                  row, self.mapped_ranges, self.state)
        return {
            "handled": handled,
            "frame": frame,
            "eax_before": eax_before,
            "flags_before": flags_before,
            "esp_after": self.engine.reg_read(x86_const.UC_X86_REG_ESP),
            "eip_after": self.engine.reg_read(x86_const.UC_X86_REG_EIP),
            "eax_after": self.engine.reg_read(x86_const.UC_X86_REG_EAX),
            "flags_after": (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                            EFLAGS_MASK),
        }

    def create_heap(self, *, initial_size: int = 4096,
                    maximum_size: int = 0, flags: int = 0) -> int:
        result = self.call_api("HeapCreate", flags, initial_size, maximum_size)
        self.assertTrue(result["handled"])
        self.assertEqual(result["eip_after"], RETURN_ADDRESS)
        self.assertEqual(result["esp_after"], STACK_BASE + 16)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                         EFLAGS_MASK, result["flags_before"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )
        return int(result["eax_after"])

    def alloc(self, heap: int, flags: int, size: int) -> dict:
        return self.call_api("HeapAlloc", heap, flags, size)

    def assert_stdcall(self, result: dict, expected_eax: int) -> None:
        self.assertTrue(result["handled"])
        self.assertEqual(result["esp_after"], STACK_BASE + 16)
        self.assertEqual(result["eip_after"], RETURN_ADDRESS)
        self.assertEqual(result["eax_after"], expected_eax)
        self.assertEqual(result["flags_after"], result["flags_before"])
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )

    def test_first_fit_alignment_zero_flag_and_native_block_metadata(self) -> None:
        heap = self.create_heap()
        first = heap + HEAP_HEADER_SIZE
        self.engine.mem_write(first, bytes([0xA5]) * 16)
        result = self.alloc(heap, 0x01, 5)  # HEAP_NO_SERIALIZE, no zeroing.
        self.assert_stdcall(result, first)
        self.assertEqual(bytes(self.engine.mem_read(first, 5)), bytes([0xA5]) * 5)

        second = first + 8
        self.engine.mem_write(second, bytes([0x5A]) * 8)
        result = self.alloc(heap, 0x09, 5)  # Both supported flags.
        self.assert_stdcall(result, second)
        self.assertEqual(bytes(self.engine.mem_read(second, 5)), bytes(5))
        self.assertEqual(bytes(self.engine.mem_read(second + 5, 3)),
                         bytes([0x5A]) * 3)
        metadata = self.state["heaps"][0]
        self.assertEqual(metadata["live_blocks"], 2)
        self.assertEqual(metadata["blocks"], [
            {"slot": 0, "address": first, "size": 5, "span": 8},
            {"slot": 1, "address": second, "size": 5, "span": 8},
        ])
        self.assertEqual(metadata["committed_size"], 0x8000)
        self.assertEqual(self.state["api_calls"][-1]["last_error_policy"],
                         "preserved")

    def test_zero_size_uses_distinct_aligned_eight_byte_spans_and_block_cap(self) -> None:
        heap = self.create_heap(initial_size=0)
        addresses = []
        for _ in range(HEAP_MAX_BLOCKS):
            result = self.alloc(heap, 0, 0)
            address = int(result["eax_after"])
            self.assert_stdcall(result, address)
            self.assertNotEqual(address, 0)
            self.assertEqual(address & 7, 0)
            addresses.append(address)
        self.assertEqual(addresses,
                         [heap + HEAP_HEADER_SIZE + 8 * index
                          for index in range(HEAP_MAX_BLOCKS)])
        self.assertEqual(len(set(addresses)), HEAP_MAX_BLOCKS)
        self.assertEqual(self.state["heaps"][0]["live_blocks"], HEAP_MAX_BLOCKS)
        self.assertTrue(all(block["size"] == 0 and block["span"] == 8
                            for block in self.state["heaps"][0]["blocks"]))

        blocks_before = [dict(block) for block in self.state["heaps"][0]["blocks"]]
        result = self.alloc(heap, 0, 0)
        self.assert_stdcall(result, 0)
        self.assertEqual(self.state["heaps"][0]["blocks"], blocks_before)
        self.assertEqual(self.state["heaps"][0]["live_blocks"], HEAP_MAX_BLOCKS)

    def test_fixed_heap_cutoff_capacity_and_commit_growth(self) -> None:
        heap = self.create_heap(initial_size=0, maximum_size=0x80000)
        original = self.state["heaps"][0]
        metadata_before = {key: value for key, value in original.items()}
        result = self.alloc(heap, 0, 0x7FFF8)
        self.assert_stdcall(result, 0)
        self.assertEqual(self.state["heaps"][0], metadata_before)

        accepted_size = 0x7FFF7
        result = self.alloc(heap, 0, accepted_size)
        address = heap + HEAP_HEADER_SIZE
        self.assert_stdcall(result, address)
        self.assertEqual(self.state["heaps"][0]["blocks"], [
            {"slot": 0, "address": address,
             "size": accepted_size, "span": 0x7FFF8},
        ])
        self.assertEqual(self.state["heaps"][0]["committed_size"], 0x84000)
        self.assertTrue(any(start == heap and end == heap + 0x84000
                            for start, end in self.mapped_ranges))

        metadata_before = {key: value for key, value in self.state["heaps"][0].items()}
        result = self.alloc(heap, 0, 9)
        self.assert_stdcall(result, 0)
        self.assertEqual(self.state["heaps"][0], metadata_before)

    def test_invalid_heap_and_unsupported_flags_preserve_guest_state(self) -> None:
        heap = self.create_heap(initial_size=0)
        metadata_before = {key: value for key, value in self.state["heaps"][0].items()}
        api_count_before = len(self.state["api_calls"])

        unsupported = self.alloc(heap, HEAP_ALLOC_SUPPORTED_FLAGS | 0x10, 16)
        self.assertFalse(unsupported["handled"])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), STACK_BASE)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         IMPORT_BASE + 13)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         unsupported["eax_before"])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                         EFLAGS_MASK, unsupported["flags_before"])
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 16)),
                         unsupported["frame"])
        self.assertEqual(len(self.state["api_calls"]), api_count_before)
        self.assertEqual(self.state["heaps"][0], metadata_before)
        self.assertEqual(
            struct.unpack("<I", self.engine.mem_read(TEB_BASE + 0x34, 4))[0],
            LAST_ERROR_SENTINEL,
        )

        result = self.alloc(0xDEADBEEF, 0, 16)
        self.assert_stdcall(result, 0)
        self.assertEqual(self.state["heaps"][0], metadata_before)

    def test_small_fixed_capacity_exhaustion_returns_null_without_last_error(self) -> None:
        heap = self.create_heap(initial_size=0, maximum_size=HEAP_GRANULE)
        result = self.alloc(heap, 0, HEAP_GRANULE)
        self.assert_stdcall(result, heap + HEAP_HEADER_SIZE)
        metadata_before = {key: value for key, value in self.state["heaps"][0].items()}
        result = self.alloc(heap, 0, 1)
        self.assert_stdcall(result, 0)
        self.assertEqual(self.state["heaps"][0], metadata_before)


if __name__ == "__main__":
    unittest.main()
