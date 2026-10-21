#!/usr/bin/env python3
"""Synthetic Unicorn tests for the declared guest CPUID profile."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(__file__).resolve().parent
for path in (ROOT / "tools", PRIVATE, ROOT / "out" / "private-deps"):
    if path.is_dir():
        sys.path.insert(0, str(path))

import unicorn
from unicorn import x86_const

from cpuid_oracle import apply_cpuid, cpuid_values


CODE_BASE = 0x01000000
PAGE_SIZE = 0x1000
IMPORT_IP = CODE_BASE
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD7  # Bit 1 is the architectural always-set EFLAGS bit.
OTHER_SENTINELS = {
    x86_const.UC_X86_REG_EBX: 0x11110001,
    x86_const.UC_X86_REG_ECX: 0x11110002,
    x86_const.UC_X86_REG_EDX: 0x11110003,
    x86_const.UC_X86_REG_ESI: 0x11110004,
    x86_const.UC_X86_REG_EDI: 0x11110005,
    x86_const.UC_X86_REG_ESP: 0x00100000,
    x86_const.UC_X86_REG_EBP: 0x11110007,
}
RETURN_REGISTERS = (
    x86_const.UC_X86_REG_EAX,
    x86_const.UC_X86_REG_EBX,
    x86_const.UC_X86_REG_ECX,
    x86_const.UC_X86_REG_EDX,
    x86_const.UC_X86_REG_ESI,
    x86_const.UC_X86_REG_EDI,
    x86_const.UC_X86_REG_ESP,
    x86_const.UC_X86_REG_EBP,
    x86_const.UC_X86_REG_EIP,
    x86_const.UC_X86_REG_EFLAGS,
)
LEAF_ZERO = (0x00000001, 0x756E6547, 0x6C65746E, 0x49656E69)
LEAF_ONE = (0x000006D8, 0x00000000, 0x00000000, 0x0383FBFF)
LEAF_EXTENDED_MAX = (0, 0, 0, 0)


class CpuidOracleTests(unittest.TestCase):
    def test_only_three_declared_leaves_have_values(self) -> None:
        self.assertEqual(cpuid_values(0), LEAF_ZERO)
        self.assertEqual(cpuid_values(1), LEAF_ONE)
        self.assertEqual(cpuid_values(0x80000000), LEAF_EXTENDED_MAX)
        for unsupported in (2, 0x80000001, 0xFFFFFFFF):
            with self.subTest(leaf=unsupported):
                self.assertIsNone(cpuid_values(unsupported))

    def make_engine(self, code: bytes, leaf: int) -> tuple[unicorn.Uc,
                                                            dict[str, object]]:
        engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        engine.mem_map(CODE_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        engine.mem_write(CODE_BASE, code)
        engine.reg_write(x86_const.UC_X86_REG_EIP, CODE_BASE)
        engine.reg_write(x86_const.UC_X86_REG_EAX, leaf)
        engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for register, value in OTHER_SENTINELS.items():
            engine.reg_write(register, value)
        state: dict[str, object] = {
            "status": None,
            "target": None,
        }
        return engine, state

    def snapshot(self, engine: unicorn.Uc) -> dict[int, int]:
        return {register: engine.reg_read(register)
                for register in RETURN_REGISTERS}

    def test_code_hook_emulates_cpuid_and_executes_following_instructions(self) -> None:
        # CPUID; mov esi, 0xDEADBEEF; mov edi, 0x12345678.
        code = b"\x0f\xa2\xbe\xef\xbe\xad\xde\xbf\x78\x56\x34\x12"
        engine, state = self.make_engine(code, leaf=1)
        handled: list[tuple[int, int, bool]] = []

        def on_code(uc: unicorn.Uc, address: int, size: int, _user_data: object) -> None:
            if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                result = apply_cpuid(uc, x86_const, address, size, state)
                handled.append((address, size, result))

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(handled, [(CODE_BASE, 2, True)])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EAX), LEAF_ONE[0])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EBX), LEAF_ONE[1])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ECX), LEAF_ONE[2])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDX), LEAF_ONE[3])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESI), 0xDEADBEEF)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDI), 0x12345678)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESP),
                         OTHER_SENTINELS[x86_const.UC_X86_REG_ESP])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EBP),
                         OTHER_SENTINELS[x86_const.UC_X86_REG_EBP])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         FLAGS_SENTINEL)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                         CODE_BASE + len(code))
        self.assertIsNone(state["status"])

    def test_each_supported_leaf_is_emulated_by_code_hook(self) -> None:
        for leaf, expected in (
                (0, LEAF_ZERO), (1, LEAF_ONE),
                (0x80000000, LEAF_EXTENDED_MAX)):
            with self.subTest(leaf=leaf):
                code = b"\x0f\xa2\x90"
                engine, state = self.make_engine(code, leaf=leaf)
                handled: list[bool] = []

                def on_code(uc: unicorn.Uc, address: int, size: int,
                            _user_data: object) -> None:
                    if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                        handled.append(apply_cpuid(
                            uc, x86_const, address, size, state))

                engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
                engine.emu_start(CODE_BASE, CODE_BASE + len(code))

                self.assertEqual(handled, [True])
                actual = tuple(engine.reg_read(register) for register in (
                    x86_const.UC_X86_REG_EAX,
                    x86_const.UC_X86_REG_EBX,
                    x86_const.UC_X86_REG_ECX,
                    x86_const.UC_X86_REG_EDX,
                ))
                self.assertEqual(actual, expected)
                self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                                 CODE_BASE + len(code))
                self.assertIsNone(state["status"])

    def test_unknown_leaf_stops_in_hook_without_changing_registers(self) -> None:
        code = b"\x0f\xa2\xbf\x78\x56\x34\x12"
        unknown_leaf = 0x80000001
        engine, state = self.make_engine(code, leaf=unknown_leaf)
        state["status"] = None
        registers_before = self.snapshot(engine)
        results: list[bool] = []

        def on_code(uc: unicorn.Uc, address: int, size: int, _user_data: object) -> None:
            if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                results.append(apply_cpuid(uc, x86_const, address, size, state))

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(results, [False])
        self.assertEqual(self.snapshot(engine), registers_before)
        self.assertEqual(state["status"], "GUEST_STOP_INSTRUCTION")
        self.assertEqual(state["target"], CODE_BASE)
        self.assertEqual(state["instruction_fault"], {
            "address": CODE_BASE,
            "instruction": "CPUID",
            "leaf": unknown_leaf,
            "reason": "unsupported_cpuid_leaf",
        })

    def test_unknown_basic_leaf_also_stops_without_generic_zero_results(self) -> None:
        code = b"\x0f\xa2\x90"
        engine, state = self.make_engine(code, leaf=2)
        registers_before = self.snapshot(engine)
        results: list[bool] = []

        def on_code(uc: unicorn.Uc, address: int, size: int, _user_data: object) -> None:
            if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                results.append(apply_cpuid(uc, x86_const, address, size, state))

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(results, [False])
        self.assertEqual(self.snapshot(engine), registers_before)
        self.assertEqual(state["status"], "GUEST_STOP_INSTRUCTION")
        self.assertEqual(state["target"], CODE_BASE)


if __name__ == "__main__":
    unittest.main()
