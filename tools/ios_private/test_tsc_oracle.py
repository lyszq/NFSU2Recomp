#!/usr/bin/env python3
"""Synthetic Unicorn tests for deterministic guest RDTSC handling."""
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

from tsc_oracle import TSC_PROFILE, apply_rdtsc


CODE_BASE = 0x01000000
PAGE_SIZE = 0x1000
FLAGS_SENTINEL = 0xCD7
GPR_SENTINELS = {
    x86_const.UC_X86_REG_EBX: 0x11110001,
    x86_const.UC_X86_REG_ECX: 0x11110002,
    x86_const.UC_X86_REG_ESI: 0x11110004,
    x86_const.UC_X86_REG_EDI: 0x11110005,
    x86_const.UC_X86_REG_ESP: 0x00100000,
    x86_const.UC_X86_REG_EBP: 0x11110007,
}
FP_SENTINELS = {
    x86_const.UC_X86_REG_XMM0: 0x112233445566778899AABBCCDDEEFF00,
    x86_const.UC_X86_REG_XMM3: 0xAABBCCDDEEFF00112233445566778899,
    x86_const.UC_X86_REG_FPCW: 0x027F,
    x86_const.UC_X86_REG_FPSW: 0x1200,
}
PRESERVED_REGISTERS = tuple(GPR_SENTINELS) + (
    x86_const.UC_X86_REG_EFLAGS,
) + tuple(FP_SENTINELS)


class TscOracleTests(unittest.TestCase):
    def make_engine(self, code: bytes,
                    state: dict[str, object] | None = None) -> tuple[
                        unicorn.Uc, dict[str, object]]:
        engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        engine.mem_map(CODE_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        engine.mem_write(CODE_BASE, code)
        engine.reg_write(x86_const.UC_X86_REG_EIP, CODE_BASE)
        engine.reg_write(x86_const.UC_X86_REG_EAX, 0xAABBCCDD)
        engine.reg_write(x86_const.UC_X86_REG_EDX, 0x55667788)
        engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        for register, value in GPR_SENTINELS.items():
            engine.reg_write(register, value)
        for register, value in FP_SENTINELS.items():
            engine.reg_write(register, value)
        return engine, dict(state or {})

    def snapshot_preserved(self, engine: unicorn.Uc) -> dict[int, int]:
        return {register: engine.reg_read(register)
                for register in PRESERVED_REGISTERS}

    def hook_rdtsc(self, engine: unicorn.Uc,
                   state: dict[str, object]) -> list[tuple[int, int, bool]]:
        results: list[tuple[int, int, bool]] = []

        def on_code(uc: unicorn.Uc, address: int, size: int,
                    _user_data: object) -> None:
            if bytes(uc.mem_read(address, 2)) == b"\x0f\x31":
                result = apply_rdtsc(uc, x86_const, address, size, state)
                results.append((address, size, result))

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        return results

    def test_hook_skips_native_rdtsc_and_preserves_nonresult_state(self) -> None:
        # RDTSC; mov esi, 0xDEADBEEF. The MOV proves execution resumed after
        # the hook advanced EIP past Unicorn's host-dependent RDTSC.
        code = b"\x0f\x31\xbe\xef\xbe\xad\xde"
        engine, state = self.make_engine(code, {
            "virtual_tsc_next": 0x12345678ABCDEF01,
            "virtual_tsc_increment": 1000,
        })
        preserved_before = self.snapshot_preserved(engine)
        handled = self.hook_rdtsc(engine, state)

        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(handled, [(CODE_BASE, 2, True)])
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EAX), 0xABCDEF01)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDX), 0x12345678)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESI), 0xDEADBEEF)
        for register, value in preserved_before.items():
            if register != x86_const.UC_X86_REG_ESI:
                self.assertEqual(engine.reg_read(register), value)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                         CODE_BASE + len(code))
        self.assertEqual(bytes(engine.mem_read(CODE_BASE, len(code))), code)
        self.assertEqual(state["virtual_tsc_next"], 0x12345678ABCDEF01 + 1000)
        self.assertEqual(state["rdtsc_calls"], [{
            "address": CODE_BASE,
            "value": 0x12345678ABCDEF01,
            "profile": TSC_PROFILE,
        }])

    def test_explicit_reset_replays_the_same_first_value(self) -> None:
        code = b"\x0f\x31\x90"
        observed: list[int] = []
        for _ in range(2):
            engine, state = self.make_engine(code, {
                "virtual_tsc_next": 0x1020304050607080,
                "virtual_tsc_increment": 0x100,
            })
            self.hook_rdtsc(engine, state)
            engine.emu_start(CODE_BASE, CODE_BASE + len(code))
            observed.append(state["rdtsc_calls"][0]["value"])
            self.assertEqual(state["virtual_tsc_next"],
                             0x1020304050607180)
        self.assertEqual(observed, [0x1020304050607080] * 2)

    def test_counter_splits_and_wraps_at_uint64_boundary(self) -> None:
        code = b"\x0f\x31\x0f\x31\x90"
        initial = 0xFFFFFFFFFFFFFFF0
        engine, state = self.make_engine(code, {
            "virtual_tsc_next": initial,
            "virtual_tsc_increment": 0x30,
        })
        handled = self.hook_rdtsc(engine, state)

        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(handled, [(CODE_BASE, 2, True),
                                   (CODE_BASE + 2, 2, True)])
        self.assertEqual(state["rdtsc_calls"], [
            {"address": CODE_BASE, "value": initial,
             "profile": TSC_PROFILE},
            {"address": CODE_BASE + 2, "value": 0x20,
             "profile": TSC_PROFILE},
        ])
        self.assertEqual(state["virtual_tsc_next"], 0x50)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EAX), 0x20)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDX), 0)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EFLAGS),
                         FLAGS_SENTINEL)
        for register, value in FP_SENTINELS.items():
            self.assertEqual(engine.reg_read(register), value)

    def test_zero_is_a_valid_counter_value(self) -> None:
        code = b"\x0f\x31\x90"
        engine, state = self.make_engine(code, {
            "virtual_tsc_next": 0,
            "virtual_tsc_increment": 1,
        })
        self.hook_rdtsc(engine, state)

        engine.emu_start(CODE_BASE, CODE_BASE + len(code))

        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EAX), 0)
        self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EDX), 0)
        self.assertEqual(state["virtual_tsc_next"], 1)

    def test_missing_or_malformed_profile_stops_atomically(self) -> None:
        code = b"\x0f\x31\xbe\xef\xbe\xad\xde"
        cases = (
            {},
            {"virtual_tsc_next": 1},
            {"virtual_tsc_increment": 1},
            {"virtual_tsc_next": 0, "virtual_tsc_increment": 0},
            {"virtual_tsc_next": True, "virtual_tsc_increment": 1},
            {"virtual_tsc_next": 1, "virtual_tsc_increment": False},
            {"virtual_tsc_next": -1, "virtual_tsc_increment": 1},
            {"virtual_tsc_next": 1 << 64, "virtual_tsc_increment": 1},
            {"virtual_tsc_next": 1, "virtual_tsc_increment": -1},
            {"virtual_tsc_next": 1, "virtual_tsc_increment": 1 << 64},
        )
        for config in cases:
            with self.subTest(config=config):
                engine, state = self.make_engine(code, config)
                before = self.snapshot_preserved(engine)
                handled = self.hook_rdtsc(engine, state)
                engine.emu_start(CODE_BASE, CODE_BASE + len(code))

                self.assertEqual(handled, [(CODE_BASE, 2, False)])
                self.assertEqual(self.snapshot_preserved(engine), before)
                # The MOV after RDTSC must not run after the strict stop.
                self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_ESI),
                                 GPR_SENTINELS[x86_const.UC_X86_REG_ESI])
                self.assertEqual(engine.reg_read(x86_const.UC_X86_REG_EIP),
                                 CODE_BASE)
                self.assertNotIn("rdtsc_calls", state)
                self.assertEqual(state["status"], "GUEST_STOP_INSTRUCTION")
                self.assertEqual(state["target"], CODE_BASE)
                self.assertEqual(state["instruction_fault"], {
                    "address": CODE_BASE,
                    "instruction": "RDTSC",
                    "reason": "unconfigured_virtual_tsc",
                })


if __name__ == "__main__":
    unittest.main()
