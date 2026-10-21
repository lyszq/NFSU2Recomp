#!/usr/bin/env python3
"""Synthetic Unicorn tests for the explicit QPF/QPC/GetTickCount fixture."""
from __future__ import annotations

from copy import deepcopy
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

from clock_oracle import (
    CLOCK_PROFILE,
    FNV_OFFSET,
    FNV_PRIME,
    handle_clock_import,
)


CODE_BASE = 0x00400000
STACK_BASE = 0x00500000
OUTPUT_BASE = 0x00600000
IMPORT_BASE = 0xF0000000
PAGE_SIZE = 0x1000
IMPORT_INDEX = 13
IMPORT_TAG = IMPORT_BASE + IMPORT_INDEX
IMPORT_IP = 0xF0000013
RETURN_ADDRESS = 0x00123456
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0x0CD7
FNV_MASK = 0xFFFFFFFFFFFFFFFF
INT64_MAX = 0x7FFFFFFFFFFFFFFF

GPR_SENTINELS = {
    x86_const.UC_X86_REG_EBX: 0x11110001,
    x86_const.UC_X86_REG_ECX: 0x11110002,
    x86_const.UC_X86_REG_EDX: 0x11110003,
    x86_const.UC_X86_REG_ESI: 0x11110004,
    x86_const.UC_X86_REG_EDI: 0x11110005,
    x86_const.UC_X86_REG_EBP: 0x11110006,
}
FP_SENTINELS = {
    x86_const.UC_X86_REG_XMM0: 0x112233445566778899AABBCCDDEEFF00,
    x86_const.UC_X86_REG_XMM3: 0xAABBCCDDEEFF00112233445566778899,
    x86_const.UC_X86_REG_FPCW: 0x027F,
    x86_const.UC_X86_REG_FPSW: 0x1200,
}
NONRESULT_REGISTERS = (
    x86_const.UC_X86_REG_EFLAGS,
    *GPR_SENTINELS.keys(),
    *FP_SENTINELS.keys(),
)
SNAPSHOT_REGISTERS = (
    x86_const.UC_X86_REG_EAX,
    x86_const.UC_X86_REG_EIP,
    x86_const.UC_X86_REG_ESP,
    *NONRESULT_REGISTERS,
)


def fixture_clock(**overrides: int) -> dict[str, int]:
    clock = {
        "mode": 1,
        "frequency": 1_000_000,
        "next": 1_000_000,
        "increment": 1_000,
        "query_count": 0,
        "sample_count": 0,
        "trace_hash": FNV_OFFSET,
    }
    clock.update(overrides)
    return clock


def fold_hash(words: tuple[int, ...]) -> int:
    value = FNV_OFFSET
    for word in words:
        value = ((value ^ word) * FNV_PRIME) & FNV_MASK
    return value


class ClockOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.mapped_ranges: list[tuple[int, int]] = []
        for address in (CODE_BASE, STACK_BASE, OUTPUT_BASE, IMPORT_BASE):
            self.engine.mem_map(address, PAGE_SIZE, unicorn.UC_PROT_ALL)
            self.mapped_ranges.append((address, address + PAGE_SIZE))
        self.engine.mem_write(OUTPUT_BASE, b"\xA5" * PAGE_SIZE)
        self.engine.mem_write(IMPORT_TAG, b"\x90")
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
            "clock": fixture_clock(),
        }
        self.rows = {
            name: {"library": "KERNEL32.dll", "name": name,
                   "index": IMPORT_INDEX}
            for name in ("QueryPerformanceFrequency",
                         "QueryPerformanceCounter", "GetTickCount")
        }
        self.write_frame([OUTPUT_BASE])

    def write_frame(self, arguments: list[int], *, esp: int = STACK_BASE,
                    return_address: int = RETURN_ADDRESS) -> bytes:
        words = [return_address & 0xFFFFFFFF]
        words.extend(value & 0xFFFFFFFF for value in arguments)
        frame = struct.pack("<" + "I" * len(words), *words)
        self.engine.mem_write(esp, frame)
        self.set_registers(esp)
        return frame

    def set_registers(self, esp: int) -> None:
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for register, value in GPR_SENTINELS.items():
            self.engine.reg_write(register, value)
        for register, value in FP_SENTINELS.items():
            self.engine.reg_write(register, value)
        self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)

    def call_import(self, name: str = "QueryPerformanceCounter",
                    *, row: dict[str, object] | None = None) -> bool:
        return handle_clock_import(
            self.engine, x86_const, unicorn, row or self.rows[name],
            self.mapped_ranges, self.state)

    def register_snapshot(self) -> dict[int, int]:
        return {register: self.engine.reg_read(register)
                for register in SNAPSHOT_REGISTERS}

    def mapped_memory_snapshot(self) -> list[tuple[int, bytes]]:
        return [(start, bytes(self.engine.mem_read(start, end - start)))
                for start, end in self.mapped_ranges]

    def assert_completed(self, *, result: int, frame_size: int,
                         esp: int = STACK_BASE,
                         return_address: int = RETURN_ADDRESS) -> None:
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), result)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         return_address)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         (esp + frame_size) & 0xFFFFFFFF)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         self.flags_before)
        for register, value in GPR_SENTINELS.items():
            self.assertEqual(self.engine.reg_read(register), value)
        for register, value in FP_SENTINELS.items():
            self.assertEqual(self.engine.reg_read(register), value)
        self.assertTrue(self.state["resume"])
        self.assertIsNone(self.state["status"])

    def assert_memory_fault_atomic(self, *, access: str, address: int,
                                   size: int, frame_address: int = STACK_BASE,
                                   frame_size: int = 8) -> None:
        registers_before = self.register_snapshot()
        memory_before = self.mapped_memory_snapshot()
        clock_before = deepcopy(self.state.get("clock"))
        calls_before = deepcopy(self.state["api_calls"])

        self.assertFalse(self.call_import())

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(self.mapped_memory_snapshot(), memory_before)
        self.assertEqual(self.state.get("clock"), clock_before)
        self.assertEqual(self.state["api_calls"], calls_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_MEMORY")
        self.assertEqual(self.state["target"], address & 0xFFFFFFFF)
        self.assertEqual(self.state["memory_fault"], {
            "access": access, "address": address, "size": size,
        })
        self.assertFalse(self.state["resume"])

    def assert_api_state_atomic(self, *, reason: str, name: str,
                                frame_size: int = 8) -> None:
        registers_before = self.register_snapshot()
        memory_before = self.mapped_memory_snapshot()
        clock_before = deepcopy(self.state.get("clock"))
        calls_before = deepcopy(self.state["api_calls"])

        self.assertFalse(self.call_import(name))

        self.assertEqual(self.register_snapshot(), registers_before)
        self.assertEqual(self.mapped_memory_snapshot(), memory_before)
        self.assertEqual(self.state.get("clock"), clock_before)
        self.assertEqual(self.state["api_calls"], calls_before)
        self.assertEqual(self.state["status"], "GUEST_STOP_API_STATE")
        self.assertEqual(self.state["target"], 0)
        self.assertEqual(self.state["api_state_fault"], {
            "api": name, "address": IMPORT_IP, "reason": reason,
        })
        self.assertFalse(self.state["resume"])

    def test_real_unicorn_call_hook_handles_qpc_and_resumes(self) -> None:
        # call eax; nop. The call enters the mapped import stub; the code hook
        # handles it and resumes at the real return address after CALL.
        code = b"\xFF\xD0\x90"
        self.engine.mem_write(CODE_BASE, code)
        initial_esp = STACK_BASE + 0x200
        self.engine.mem_write(initial_esp, struct.pack("<I", OUTPUT_BASE))
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, CODE_BASE)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, initial_esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, IMPORT_TAG)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        self.flags_before = self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS)
        for register, value in GPR_SENTINELS.items():
            if register != x86_const.UC_X86_REG_EDI:
                self.engine.reg_write(register, value)
        for register, value in FP_SENTINELS.items():
            self.engine.reg_write(register, value)
        self.state["last_ip"] = CODE_BASE
        handled: list[bool] = []

        def on_code(uc: unicorn.Uc, address: int, _size: int,
                    _user_data: object) -> None:
            if address == IMPORT_TAG:
                handled.append(handle_clock_import(
                    uc, x86_const, unicorn,
                    self.rows["QueryPerformanceCounter"],
                    self.mapped_ranges, self.state))

        self.engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        self.engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(handled, [True])
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), 1)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         CODE_BASE + len(code))
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         initial_esp + 4)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         self.flags_before)
        for register, value in GPR_SENTINELS.items():
            self.assertEqual(self.engine.reg_read(register), value)
        for register, value in FP_SENTINELS.items():
            self.assertEqual(self.engine.reg_read(register), value)
        self.assertEqual(struct.unpack("<Q", self.engine.mem_read(
            OUTPUT_BASE, 8))[0], 1_000_000)
        self.assertEqual(self.state["clock"], fixture_clock(
            next=1_001_000, query_count=1, sample_count=1,
            trace_hash=fold_hash((2, 1_000_000))))
        self.assertEqual(self.state["api_calls"][0]["return_address"],
                         CODE_BASE + 2)
        self.assertEqual(self.state["api_calls"][0]["arguments"],
                         [OUTPUT_BASE])

    def test_qpf_qpc_and_tick_update_query_sample_and_hash_in_order(self) -> None:
        self.write_frame([OUTPUT_BASE])
        self.assertTrue(self.call_import("QueryPerformanceFrequency"))
        self.assert_completed(result=1, frame_size=8)
        self.assertEqual(struct.unpack("<Q", self.engine.mem_read(
            OUTPUT_BASE, 8))[0], 1_000_000)

        self.write_frame([OUTPUT_BASE + 16])
        self.assertTrue(self.call_import("QueryPerformanceCounter"))
        self.assert_completed(result=1, frame_size=8)
        self.assertEqual(struct.unpack("<Q", self.engine.mem_read(
            OUTPUT_BASE + 16, 8))[0], 1_000_000)

        self.write_frame([])
        self.assertTrue(self.call_import("GetTickCount"))
        self.assert_completed(result=1001, frame_size=4)

        expected_hash = fold_hash((
            1, 1_000_000, 2, 1_000_000, 3, 1001,
        ))
        self.assertEqual(self.state["clock"], fixture_clock(
            next=1_002_000, query_count=3, sample_count=2,
            trace_hash=expected_hash))
        self.assertEqual([api["name"] for api in self.state["api_calls"]], [
            "QueryPerformanceFrequency", "QueryPerformanceCounter",
            "GetTickCount",
        ])
        self.assertEqual([api["clock_opcode"] for api in self.state["api_calls"]],
                         [1, 2, 3])
        self.assertEqual([api["clock_value"] for api in self.state["api_calls"]],
                         [1_000_000, 1_000_000, 1001])
        self.assertTrue(all(api["profile"] == CLOCK_PROFILE
                            for api in self.state["api_calls"]))

    def test_qpf_write_can_alias_frame_because_all_words_are_snapshotted(self) -> None:
        frame = self.write_frame([STACK_BASE])

        self.assertTrue(self.call_import("QueryPerformanceFrequency"))

        self.assert_completed(result=1, frame_size=8)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, 8)),
                         struct.pack("<Q", 1_000_000))
        api = self.state["api_calls"][0]
        self.assertEqual(api["return_address"], RETURN_ADDRESS)
        self.assertEqual(api["arguments"], [STACK_BASE])
        self.assertNotEqual(bytes(self.engine.mem_read(STACK_BASE, 8)), frame)

    def test_null_overflowing_readonly_and_partial_outputs_fault_atomically(self) -> None:
        cases = (
            (0, "null"),
            (0xFFFFFFFC, "overflow"),
            (OUTPUT_BASE + PAGE_SIZE - 4, "partial"),
        )
        for pointer, label in cases:
            with self.subTest(label=label):
                if pointer == 0xFFFFFFFC:
                    high = 0xFFFFF000
                    self.engine.mem_map(high, PAGE_SIZE, unicorn.UC_PROT_ALL)
                    self.mapped_ranges.append((high, 0x100000000))
                self.write_frame([pointer])
                self.assert_memory_fault_atomic(
                    access="write", address=pointer, size=8)
                if pointer == 0xFFFFFFFC:
                    self.engine.mem_unmap(0xFFFFF000, PAGE_SIZE)
                    self.mapped_ranges.pop()

        self.write_frame([OUTPUT_BASE])
        self.engine.mem_protect(OUTPUT_BASE, PAGE_SIZE, unicorn.UC_PROT_READ)
        self.assert_memory_fault_atomic(
            access="write", address=OUTPUT_BASE, size=8)

        self.engine.mem_map(0, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges.append((0, PAGE_SIZE))
        self.write_frame([0])
        self.assert_memory_fault_atomic(access="write", address=0, size=8)
        self.engine.mem_unmap(0, PAGE_SIZE)
        self.mapped_ranges.pop()

    def test_invalid_or_partial_frames_fault_without_clock_changes(self) -> None:
        self.set_registers(0x00700000)
        self.assert_memory_fault_atomic(
            access="read", address=0x00700000, size=8)

        self.write_frame([OUTPUT_BASE])
        self.mapped_ranges = [
            region for region in self.mapped_ranges
            if region[0] != STACK_BASE
        ] + [(STACK_BASE, STACK_BASE + 7)]
        self.assert_memory_fault_atomic(
            access="read", address=STACK_BASE, size=8)

        self.mapped_ranges = [
            (start, stop) for start, stop in self.mapped_ranges
            if start != STACK_BASE
        ] + [(STACK_BASE, STACK_BASE + PAGE_SIZE)]
        self.engine.mem_protect(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_WRITE)
        self.assert_memory_fault_atomic(
            access="read", address=STACK_BASE, size=8)

    def test_qpc_output_at_uint32_boundary_is_rejected_as_a_full_qword(self) -> None:
        high = 0xFFFFF000
        if not any(start == high for start, _ in self.mapped_ranges):
            self.engine.mem_map(high, PAGE_SIZE, unicorn.UC_PROT_ALL)
            self.mapped_ranges.append((high, 0x100000000))
        self.engine.mem_write(0xFFFFFFFC, b"\xCC" * 4)
        self.write_frame([0xFFFFFFFC])
        self.assert_memory_fault_atomic(
            access="write", address=0xFFFFFFFC, size=8)

    def test_sample_at_int64_limit_stops_before_output_or_clock_mutation(self) -> None:
        for name in ("QueryPerformanceCounter", "GetTickCount"):
            with self.subTest(name=name):
                self.state["clock"] = fixture_clock(next=INT64_MAX)
                if name == "QueryPerformanceCounter":
                    self.write_frame([OUTPUT_BASE])
                    frame_size = 8
                else:
                    self.write_frame([])
                    frame_size = 4
                self.assert_api_state_atomic(
                    reason="counter_overflow", name=name,
                    frame_size=frame_size)

    def test_unconfigured_and_malformed_clock_profiles_stop_atomically(self) -> None:
        invalid_profiles = (
            None,
            {},
            fixture_clock(mode=2),
            fixture_clock(frequency=0),
            fixture_clock(frequency=INT64_MAX + 1),
            fixture_clock(next=-1),
            fixture_clock(next=INT64_MAX + 1),
            fixture_clock(increment=0),
            fixture_clock(increment=INT64_MAX + 1),
            fixture_clock(query_count=True),
            fixture_clock(sample_count=-1),
            fixture_clock(query_count=0, sample_count=1),
            fixture_clock(trace_hash=1 << 64),
            {**fixture_clock(), "host_clock": True},
        )
        for profile in invalid_profiles:
            with self.subTest(profile=profile):
                self.state["clock"] = deepcopy(profile)
                self.write_frame([OUTPUT_BASE])
                self.assert_api_state_atomic(
                    reason="unconfigured_clock_profile",
                    name="QueryPerformanceCounter")

        del self.state["clock"]
        self.write_frame([OUTPUT_BASE])
        self.assert_api_state_atomic(
            reason="unconfigured_clock_profile",
            name="QueryPerformanceCounter")

    def test_query_counter_cannot_wrap(self) -> None:
        self.state["clock"] = fixture_clock(query_count=0xFFFFFFFFFFFFFFFF)
        self.write_frame([OUTPUT_BASE])
        self.assert_api_state_atomic(
            reason="query_count_overflow", name="QueryPerformanceFrequency")

    def test_malformed_api_log_stops_before_output_or_clock_mutation(self) -> None:
        self.state["api_calls"] = None
        self.write_frame([OUTPUT_BASE])
        self.assert_api_state_atomic(
            reason="invalid_api_log", name="QueryPerformanceCounter")

    def test_wrong_library_or_export_is_unsupported_without_side_effects(self) -> None:
        self.set_registers(0x00700000)
        cases = (
            {"library": "USER32.dll", "name": "QueryPerformanceCounter",
             "index": IMPORT_INDEX},
            {"library": "KERNEL32.dll", "name": "GetTickCount64",
             "index": IMPORT_INDEX},
            {"library": "kernel32.dll", "name": "queryperformancecounter",
             "index": IMPORT_INDEX},
        )
        for row in cases:
            with self.subTest(row=row):
                registers_before = self.register_snapshot()
                clock_before = deepcopy(self.state["clock"])
                calls_before = deepcopy(self.state["api_calls"])
                state_before = deepcopy(self.state)

                self.assertFalse(self.call_import(row=row))

                self.assertEqual(self.register_snapshot(), registers_before)
                self.assertEqual(self.state["clock"], clock_before)
                self.assertEqual(self.state["api_calls"], calls_before)
                self.assertEqual(self.state, state_before)


if __name__ == "__main__":
    unittest.main()
