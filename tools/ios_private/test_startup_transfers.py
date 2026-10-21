#!/usr/bin/env python3
"""Synthetic transfer and REP-hook tests; no proprietary game input is read."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import os
import struct
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(__file__).resolve().parent
PRIVATE_DEPS = ROOT / "out" / "private-deps"
for path in (ROOT / "tools", PRIVATE, PRIVATE_DEPS):
    if path.is_dir():
        sys.path.insert(0, str(path))

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
import unicorn
from unicorn import x86_const

from generate_startup import observed_startup_targets, startup_lifter_class
from lift import Lifter, Unsupported
import startup_oracle


BASE = 0x00400000


class StartupTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.startup_lifter = startup_lifter_class(Lifter, Unsupported)

    def make_lifter(self, code: bytes):
        lifter = self.startup_lifter.__new__(self.startup_lifter)
        lifter.comments = False
        lifter.trap = False
        lifter.traps = 0
        lifter.trap_kinds = Counter()
        lifter.hooks = set()
        lifter.watch = False
        lifter.cov = False
        lifter.secs = [(".text", BASE, len(code), bytes(code))]
        lifter.TVA = BASE
        lifter.TSZ = len(code)
        lifter.TDATA = bytes(code)
        lifter.md = Cs(CS_ARCH_X86, CS_MODE_32)
        lifter.md.detail = True
        return lifter

    def lift(self, code: bytes) -> str:
        lifter = self.make_lifter(code)
        with patch.dict(os.environ, {"FLAGOPT": "0", "RETEIP": "1", "X87OPT": "0"}):
            body, _targets = lifter.lift(BASE)
        return body

    def test_rdtsc_uses_explicit_execution_fixture(self) -> None:
        body = self.lift(b"\x0f\x31\xc3")
        self.assertIn("guest_execution_rdtsc(c);", body)
        self.assertNotIn("rdtsc_shim", body)

    def test_dynamic_indirect_jump_uses_tail_dispatch_without_push(self) -> None:
        body = self.lift(b"\xff\xe0")  # jmp eax

        self.assertIn("guest_execution_tail(c, c->eax); return;", body)
        self.assertNotIn("PUSH32(", body)
        self.assertNotIn("dispatch_indirect(", body)

    def test_in_text_direct_jump_remains_a_local_control_flow_edge(self) -> None:
        body = self.lift(b"\xeb\x00\xc3")  # jmp to the in-text ret

        self.assertIn("goto L_00400002;", body)
        self.assertNotIn("guest_execution_tail(", body)
        self.assertNotIn("dispatch_indirect(", body)

    def test_external_direct_jump_uses_tail_dispatch_without_push(self) -> None:
        target = BASE + 0x100
        displacement = target - (BASE + 5)
        body = self.lift(b"\xe9" + struct.pack("<i", displacement))

        self.assertIn(f"guest_execution_tail(c, 0x{target:x}u); return;", body)
        self.assertNotIn("PUSH32(", body)
        self.assertNotIn("dispatch_indirect(", body)

    def test_external_loop_edge_uses_tail_dispatch_without_push(self) -> None:
        target = BASE + 0x80
        body = self.lift(b"\xe2\x7e\xc3")  # loop outside .text; ret fallthrough

        self.assertIn("c->ecx--;", body)
        self.assertIn(
            f"if(c->ecx != 0u) {{ guest_execution_tail(c, 0x{target:x}u); return; }}",
            body,
        )
        self.assertNotIn("PUSH32(", body)

    def test_external_direct_call_pushes_return_address_and_uses_call_dispatch(self) -> None:
        target = BASE + 0x100
        displacement = target - (BASE + 5)
        body = self.lift(b"\xe8" + struct.pack("<i", displacement))

        self.assertIn(
            f"PUSH32(0x{BASE + 5:x}u); dispatch_indirect(c, 0x{target:x}u);",
            body,
        )
        self.assertNotIn("guest_execution_tail(", body)

    def test_indirect_call_reads_target_before_push_and_uses_call_dispatch(self) -> None:
        body = self.lift(b"\xff\xd0\xc3")  # call eax; ret
        capture = body.index("uint32_t _ct = c->eax;")
        push = body.index(f"PUSH32(0x{BASE + 2:x}u);")
        dispatch = body.index("dispatch_indirect(c, _ct);")

        self.assertLess(capture, push)
        self.assertLess(push, dispatch)
        self.assertNotIn("guest_execution_tail(", body)

    def test_observed_targets_merge_calls_and_indirect_jumps_stably(self) -> None:
        reference = {
            "direct_calls": [
                {"ip": 0x100, "target": 0x1000},
                {"ip": 0x120, "target": 0x2000},
            ],
            "indirect_jumps": [
                {"ip": 0x140, "target": 0x3000},
                {"ip": 0x160, "target": 0x1000},
                {"ip": 0x180, "target": 0x4000},
            ],
        }

        self.assertEqual(
            observed_startup_targets(reference),
            [0x1000, 0x2000, 0x3000, 0x4000],
        )


class RepHookNormalizationTests(unittest.TestCase):
    CODE_BASE = 0x00100000
    SOURCE = 0x00200000
    DESTINATION = 0x00300000
    STACK = 0x00400000
    PAGE = 0x1000

    def run_guest(self, code: bytes, *, registers: dict[str, int],
                  source: bytes = b"abcdefgh", destination: bytes = b"\0" * 8):
        engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        for address in (self.CODE_BASE, self.SOURCE, self.DESTINATION, self.STACK):
            engine.mem_map(address, self.PAGE)
        engine.mem_write(self.CODE_BASE, code)
        engine.mem_write(self.SOURCE, source)
        engine.mem_write(self.DESTINATION, destination)

        end = self.CODE_BASE + len(code)
        esp = self.STACK + self.PAGE - 4
        engine.mem_write(esp, struct.pack("<I", end))
        engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        engine.reg_write(x86_const.UC_X86_REG_EFLAGS, 0x202)
        register_ids = {
            "eax": x86_const.UC_X86_REG_EAX,
            "ebx": x86_const.UC_X86_REG_EBX,
            "ecx": x86_const.UC_X86_REG_ECX,
            "esi": x86_const.UC_X86_REG_ESI,
            "edi": x86_const.UC_X86_REG_EDI,
        }
        for name, value in registers.items():
            engine.reg_write(register_ids[name], value)
        if "esi" not in registers:
            engine.reg_write(x86_const.UC_X86_REG_ESI, self.SOURCE)
        if "edi" not in registers:
            engine.reg_write(x86_const.UC_X86_REG_EDI, self.DESTINATION)

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        state = {"rep_ip": None}
        raw = []
        normalized = []
        rep_events = []

        def on_code(uc, address, size, _user_data):
            instruction = next(md.disasm(bytes(uc.mem_read(address, size)), address))
            mnemonic = instruction.mnemonic
            repeated = startup_oracle._is_rep_continuation(
                state, int(address), mnemonic)
            event = {
                "ip": int(address),
                "mnemonic": mnemonic,
                "ecx": int(uc.reg_read(x86_const.UC_X86_REG_ECX)),
                "continuation": repeated,
            }
            raw.append(event)
            if not repeated:
                normalized.append(event)
            if mnemonic.split()[0] in ("rep", "repe", "repz", "repne", "repnz"):
                rep_events.append(event)

        engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
        engine.emu_start(self.CODE_BASE, end)
        return {
            "raw": raw,
            "normalized": normalized,
            "rep": rep_events,
            "ecx": int(engine.reg_read(x86_const.UC_X86_REG_ECX)),
            "ebx": int(engine.reg_read(x86_const.UC_X86_REG_EBX)),
            "zf": bool(engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & 0x40),
        }

    def test_rep_movsb_hook_counts_for_ecx_zero_one_and_two(self) -> None:
        for initial_ecx, raw_rep_callbacks in ((0, 1), (1, 2), (2, 3)):
            with self.subTest(ecx=initial_ecx):
                result = self.run_guest(
                    b"\xf3\xa4\xc3",  # rep movsb; ret
                    registers={"ecx": initial_ecx},
                )

                self.assertEqual(len(result["rep"]), raw_rep_callbacks)
                self.assertEqual(
                    sum(not event["continuation"] for event in result["rep"]), 1)
                self.assertEqual(len(result["raw"]), raw_rep_callbacks + 1)
                self.assertEqual(len(result["normalized"]), 2)

    def test_repe_cmpsb_early_exit_is_one_guest_instruction(self) -> None:
        result = self.run_guest(
            b"\xf3\xa6\xc3",  # repe cmpsb; ret
            registers={"ecx": 4},
            source=b"ABCDxxxx",
            destination=b"XBCDxxxx",
        )

        self.assertEqual(result["ecx"], 3)
        self.assertFalse(result["zf"])
        self.assertEqual([event["continuation"] for event in result["rep"]], [False])
        self.assertEqual(len(result["raw"]), 2)
        self.assertEqual(len(result["normalized"]), 2)

    def test_branching_back_to_rep_ip_starts_a_new_instruction_occurrence(self) -> None:
        # mov ebx,2; again: mov ecx,1; rep movsb; dec ebx; jne again; ret
        code = bytes.fromhex("bb02000000b901000000f3a44b75f6c3")
        result = self.run_guest(code, registers={"ebx": 2})
        first_ip = self.CODE_BASE + 10
        rep_events = [event for event in result["rep"] if event["ip"] == first_ip]

        self.assertEqual(len(rep_events), 4)
        starts = [event for event in rep_events if not event["continuation"]]
        self.assertEqual(len(starts), 2)
        self.assertEqual([event["ecx"] for event in starts], [1, 1])
        self.assertEqual(result["ecx"], 0)
        self.assertEqual(result["ebx"], 0)

    def test_same_ip_non_rep_hooks_are_never_suppressed(self) -> None:
        state = {"rep_ip": None}

        self.assertFalse(startup_oracle._is_rep_continuation(state, 0x1234, "nop"))
        self.assertFalse(startup_oracle._is_rep_continuation(state, 0x1234, "nop"))


if __name__ == "__main__":
    unittest.main()
