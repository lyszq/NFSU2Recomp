#!/usr/bin/env python3
"""Synthetic heap API regressions for the private startup oracle.

These tests use only small in-memory guest fixtures; they never open the game
executable or generated lifted sources.
"""
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

import startup_oracle as oracle


STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
RETURN_ADDRESS = 0x00123456
IMPORT_IP = oracle.IMPORT_BASE + 21
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
LAST_ERROR_SENTINEL = 0x76543210
BLOCK_PAYLOAD = b"old_payload_1234"


class HeapOracleRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(oracle.TEB_BASE, oracle.TEB_SIZE,
                            unicorn.UC_PROT_ALL)
        self.engine.mem_write(oracle.TEB_BASE + oracle.LAST_ERROR_OFFSET,
                              struct.pack("<I", LAST_ERROR_SENTINEL))
        self.handle = oracle.HEAP_BASE
        self.heap_end = self.handle + 0x8000
        self.engine.mem_map(self.handle, self.heap_end - self.handle,
                            unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (oracle.TEB_BASE, oracle.TEB_BASE + oracle.TEB_SIZE),
            (self.handle, self.heap_end),
        ]
        self.heap = {
            "slot": 0,
            "handle": self.handle,
            "capacity": 0x20000,
            "initial_size": 0,
            "maximum_size": 0,
            "rounded_maximum": 0,
            "flags": 0,
            "committed_size": self.heap_end - self.handle,
            "live_blocks": 0,
            "fixed": False,
            "blocks": [],
        }
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "heaps": {0: self.heap},
            "resume": False,
            "status": None,
        }

    def last_error(self) -> int:
        return struct.unpack(
            "<I", self.engine.mem_read(
                oracle.TEB_BASE + oracle.LAST_ERROR_OFFSET, 4)
        )[0]

    def set_frame(self, name: str, arguments: tuple[int, ...], *,
                  import_ip: int = IMPORT_IP) -> tuple[int, int]:
        esp = STACK_BASE
        frame = struct.pack("<I" + "I" * len(arguments),
                            RETURN_ADDRESS, *arguments)
        self.engine.mem_write(esp, frame)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, esp)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, import_ip)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        return esp, len(frame)

    def call_free(self, handle: int, flags: int, address: int) -> bool:
        self.set_frame("HeapFree", (handle, flags, address))
        row = {"library": "KERNEL32.dll", "name": "HeapFree", "index": 21}
        return oracle._heap_free(
            self.engine, x86_const, unicorn, row,
            self.mapped_ranges, self.state)

    def assert_success_frame(self, *, argument_bytes: int,
                             expected_eax: int) -> None:
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_ESP),
            STACK_BASE + 4 + argument_bytes,
        )
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         expected_eax)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & oracle.EFLAGS_MASK,
            FLAGS_SENTINEL & oracle.EFLAGS_MASK,
        )

    def seed_heap_blocks(self, blocks: list[dict[str, int]]) -> None:
        self.heap["blocks"] = [dict(block) for block in blocks]
        self.heap["live_blocks"] = len(blocks)
        for block in blocks:
            payload = (BLOCK_PAYLOAD if block["slot"] == 0 else
                       b"second_block_123")
            size = block["size"]
            self.engine.mem_write(block["address"], payload[:size])

    def call_realloc(self, address: int, size: int, *, flags: int = 0) -> None:
        self.set_frame("HeapReAlloc", (self.handle, flags, address, size))
        row = {"library": "KERNEL32.dll", "name": "HeapReAlloc", "index": 22}
        self.assertTrue(oracle._heap_realloc(
            self.engine, x86_const, unicorn, row,
            self.mapped_ranges, self.state))

    def assert_realloc_result(self, *, expected_address: int,
                              expected_size: int) -> None:
        self.assert_success_frame(argument_bytes=16, expected_eax=expected_address)
        self.assertEqual(self.heap["blocks"][0]["address"], expected_address)
        self.assertEqual(self.heap["blocks"][0]["size"], expected_size)
        self.assertEqual(self.heap["live_blocks"], len(self.heap["blocks"]))
        self.assertEqual(self.last_error(), LAST_ERROR_SENTINEL)
        self.assertTrue(self.state["resume"])

    def test_heap_free_valid_pointer_preserves_last_error_and_supported_flags(self) -> None:
        address = self.handle + oracle.HEAP_HEADER_SIZE
        self.seed_heap_blocks([{
            "slot": 0, "address": address, "size": len(BLOCK_PAYLOAD),
            "span": 16,
        }])

        self.assertTrue(self.call_free(self.handle, 1, address))

        self.assert_success_frame(argument_bytes=12, expected_eax=1)
        self.assertEqual(self.last_error(), LAST_ERROR_SENTINEL)
        self.assertEqual(self.heap["blocks"], [])
        self.assertEqual(self.heap["live_blocks"], 0)
        self.assertTrue(self.state["resume"])

    def test_heap_free_invalid_heap_or_pointer_fails_and_sets_last_error(self) -> None:
        address = self.handle + oracle.HEAP_HEADER_SIZE
        block = {"slot": 0, "address": address,
                 "size": len(BLOCK_PAYLOAD), "span": 16}

        for label, handle, pointer in (
                ("invalid heap", self.handle + oracle.HEAP_ARENA_SIZE, address),
                ("invalid pointer", self.handle, address + 0x100)):
            with self.subTest(case=label):
                self.engine.mem_write(
                    oracle.TEB_BASE + oracle.LAST_ERROR_OFFSET,
                    struct.pack("<I", LAST_ERROR_SENTINEL),
                )
                self.heap["blocks"] = [dict(block)]
                self.heap["live_blocks"] = 1
                before = [dict(item) for item in self.heap["blocks"]]

                self.assertTrue(self.call_free(handle, 0, pointer))

                self.assert_success_frame(argument_bytes=12, expected_eax=0)
                self.assertEqual(self.last_error(), oracle.ERROR_INVALID_PARAMETER)
                self.assertEqual(self.heap["blocks"], before)
                self.assertEqual(self.heap["live_blocks"], 1)
                self.assertTrue(self.state["resume"])

    def test_heap_free_unsupported_flags_stops_without_mutating_frame_or_heap(self) -> None:
        address = self.handle + oracle.HEAP_HEADER_SIZE
        block = {"slot": 0, "address": address,
                 "size": len(BLOCK_PAYLOAD), "span": 16}
        self.seed_heap_blocks([block])
        esp, frame_size = self.set_frame("HeapFree", (self.handle, 2, address))
        before_frame = bytes(self.engine.mem_read(esp, frame_size))
        before_blocks = [dict(item) for item in self.heap["blocks"]]
        before_flags = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        oracle.EFLAGS_MASK)

        handled = oracle._heap_free(
            self.engine, x86_const, unicorn,
            {"library": "KERNEL32.dll", "name": "HeapFree", "index": 21},
            self.mapped_ranges, self.state)

        self.assertFalse(handled)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP), esp)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP), IMPORT_IP)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX), EAX_SENTINEL)
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & oracle.EFLAGS_MASK,
            before_flags,
        )
        self.assertEqual(bytes(self.engine.mem_read(esp, frame_size)), before_frame)
        self.assertEqual(self.last_error(), LAST_ERROR_SENTINEL)
        self.assertEqual(self.heap["blocks"], before_blocks)
        self.assertEqual(self.state["api_calls"], [])
        self.assertFalse(self.state["resume"])

    def test_heap_realloc_in_place_commits_next_granule_without_losing_page_data(self) -> None:
        address = self.handle + oracle.HEAP_HEADER_SIZE
        old_size = len(BLOCK_PAYLOAD)
        self.seed_heap_blocks([{
            "slot": 0, "address": address, "size": old_size,
            "span": 16,
        }])
        page_marker = b"keep_existing_page_bytes"
        self.engine.mem_write(self.handle + 0x7000, page_marker)
        requested_size = 0x5000

        self.call_realloc(address, requested_size)

        self.assert_realloc_result(expected_address=address,
                                   expected_size=requested_size)
        self.assertEqual(self.heap["committed_size"], 0xC000)
        self.assertIn((self.handle, self.handle + 0xC000), self.mapped_ranges)
        self.assertEqual(bytes(self.engine.mem_read(address, old_size)),
                         BLOCK_PAYLOAD)
        self.assertEqual(bytes(self.engine.mem_read(self.handle + 0x7000,
                                                    len(page_marker))),
                         page_marker)
        self.assertEqual(bytes(self.engine.mem_read(self.handle + 0x9000,
                                                    0x3000)), bytes(0x3000))

    def test_heap_realloc_move_commits_next_granule_and_preserves_old_page_data(self) -> None:
        first = self.handle + oracle.HEAP_HEADER_SIZE
        second = first + 16
        old_size = len(BLOCK_PAYLOAD)
        self.seed_heap_blocks([
            {"slot": 0, "address": first, "size": old_size, "span": 16},
            {"slot": 1, "address": second, "size": 16, "span": 16},
        ])
        page_marker = b"retained_page_sentinel"
        self.engine.mem_write(self.handle + 0x7000, page_marker)
        requested_size = 0x5000
        expected_address = second + 16

        self.call_realloc(first, requested_size)

        self.assert_realloc_result(expected_address=expected_address,
                                   expected_size=requested_size)
        self.assertEqual(self.heap["blocks"][1]["address"], second)
        self.assertEqual(self.heap["committed_size"], 0xC000)
        self.assertIn((self.handle, self.handle + 0xC000), self.mapped_ranges)
        self.assertEqual(bytes(self.engine.mem_read(expected_address, old_size)),
                         BLOCK_PAYLOAD)
        self.assertEqual(bytes(self.engine.mem_read(first, old_size)),
                         BLOCK_PAYLOAD)
        self.assertEqual(bytes(self.engine.mem_read(second, 16)),
                         b"second_block_123")
        self.assertEqual(bytes(self.engine.mem_read(self.handle + 0x7000,
                                                    len(page_marker))),
                         page_marker)
        self.assertEqual(bytes(self.engine.mem_read(self.handle + 0x9000,
                                                    0x3000)), bytes(0x3000))


if __name__ == "__main__":
    unittest.main()
