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
LEAF_EXTENDED_FEATURES = (0, 0, 0, 0)
NONRESULT_FP_REGISTERS = (
    x86_const.UC_X86_REG_XMM0,
    x86_const.UC_X86_REG_XMM3,
    x86_const.UC_X86_REG_FPCW,
    x86_const.UC_X86_REG_FPSW,
)
FP_SENTINELS = {
    x86_const.UC_X86_REG_XMM0: 0x112233445566778899AABBCCDDEEFF00,
    x86_const.UC_X86_REG_XMM3: 0xAABBCCDDEEFF00112233445566778899,
    x86_const.UC_X86_REG_FPCW: 0x027F,
    x86_const.UC_X86_REG_FPSW: 0x1200,
}


class CpuidOracleTests(unittest.TestCase):
    def test_only_four_declared_leaves_have_values(self) -> None:
        self.assertEqual(cpuid_values(0), LEAF_ZERO)
        self.assertEqual(cpuid_values(1), LEAF_ONE)
        self.assertEqual(cpuid_values(0x80000000), LEAF_EXTENDED_MAX)
        self.assertEqual(cpuid_values(0x80000001), LEAF_EXTENDED_FEATURES)
        for unsupported in (2, 0x80000002, 0xFFFFFFFF):
            with self.subTest(leaf=unsupported):
                self.assertIsNone(cpuid_values(unsupported))

    def test_leaf_one_advertises_sse_but_not_sse2(self) -> None:
        values = cpuid_values(1)
        self.assertIsNotNone(values)
        assert values is not None
        edx = values[3]
        self.assertEqual(edx & (1 << 25), 1 << 25)  # SSE / feature 6.
        self.assertEqual(edx & (1 << 26), 0)  # SSE2 / feature 10.

    def test_extended_feature_leaf_advertises_no_amd_extensions(self) -> None:
        values = cpuid_values(0x80000001)
        self.assertEqual(values, (0, 0, 0, 0))
        assert values is not None
        eax, ebx, ecx, edx = values
        self.assertEqual((eax, ebx), (0, 0))
        self.assertEqual(ecx, 0)
        self.assertEqual(edx, 0)
        # In particular, do not advertise SVM/ABM/SSE4a, NX, long mode,
        # RDTSCP, or either of the two AMD 3DNow feature bits.
        for bit in (0, 2, 5, 6, 8, 11, 16, 21):
            self.assertEqual(ecx & (1 << bit), 0)
        for bit in (11, 20, 27, 29, 30, 31):
            self.assertEqual(edx & (1 << bit), 0)

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
        for register, value in FP_SENTINELS.items():
            engine.reg_write(register, value)
        state: dict[str, object] = {
            "status": None,
            "target": None,
        }
        return engine, state

    def snapshot(self, engine: unicorn.Uc) -> dict[int, int]:
        return {register: engine.reg_read(register)
                for register in RETURN_REGISTERS + NONRESULT_FP_REGISTERS}

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
        for register, value in FP_SENTINELS.items():
            self.assertEqual(engine.reg_read(register), value)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                         CODE_BASE + len(code))
        self.assertIsNone(state["status"])

    def test_each_supported_leaf_is_emulated_by_code_hook(self) -> None:
        for leaf, expected in (
                (0, LEAF_ZERO), (1, LEAF_ONE),
                (0x80000000, LEAF_EXTENDED_MAX),
                (0x80000001, LEAF_EXTENDED_FEATURES)):
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

    def test_extended_leaf_hook_skips_cpuid_and_preserves_nonresult_state(self) -> None:
        # CPUID; mov esi, 0xDEADBEEF. The instruction after CPUID must run.
        code = b"\x0f\xa2\xbe\xef\xbe\xad\xde"
        engine, state = self.make_engine(code, leaf=0x80000001)
        handled: list[bool] = []

        def on_code(uc: unicorn.Uc, address: int, size: int,
                    _user_data: object) -> None:
            if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                handled.append(apply_cpuid(uc, x86_const, address, size, state))

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(handled, [True])
        self.assertEqual(tuple(engine.reg_read(register) for register in (
            x86_const.UC_X86_REG_EAX,
            x86_const.UC_X86_REG_EBX,
            x86_const.UC_X86_REG_ECX,
            x86_const.UC_X86_REG_EDX,
        )), LEAF_EXTENDED_FEATURES)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESI), 0xDEADBEEF)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDI),
                         OTHER_SENTINELS[x86_const.UC_X86_REG_EDI])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESP),
                         OTHER_SENTINELS[x86_const.UC_X86_REG_ESP])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EBP),
                         OTHER_SENTINELS[x86_const.UC_X86_REG_EBP])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         FLAGS_SENTINEL)
        for register, value in FP_SENTINELS.items():
            self.assertEqual(engine.reg_read(register), value)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                         CODE_BASE + len(code))
        self.assertEqual(state["cpuid_calls"], [{
            "address": CODE_BASE,
            "leaf": 0x80000001,
            "eax": 0,
            "ebx": 0,
            "ecx": 0,
            "edx": 0,
        }])

    def test_unknown_leaf_stops_in_hook_without_changing_registers(self) -> None:
        code = b"\x0f\xa2\xbf\x78\x56\x34\x12"
        for unknown_leaf in (0x80000002, 0xFFFFFFFF):
            with self.subTest(leaf=unknown_leaf):
                engine, state = self.make_engine(code, leaf=unknown_leaf)
                registers_before = self.snapshot(engine)
                results: list[bool] = []

                def on_code(uc: unicorn.Uc, address: int, size: int,
                            _user_data: object) -> None:
                    if bytes(uc.mem_read(address, 2)) == b"\x0f\xa2":
                        results.append(apply_cpuid(
                            uc, x86_const, address, size, state))

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
