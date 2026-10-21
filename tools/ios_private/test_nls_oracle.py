#!/usr/bin/env python3
"""Compare the synthetic Unicorn NLS imports with the Windows CP1252 capture."""
from __future__ import annotations

import json
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


FIXTURE = ROOT / "tests" / "fixtures" / "windows_nls_cp1252.json"
STACK_BASE = 0x00500000
PAGE_SIZE = 0x1000
DATA_BASE = 0x00200000
SRC_A = DATA_BASE + 0x100
SRC_W = DATA_BASE + 0x400
OUT_BASE = DATA_BASE + 0x900
OUT_CAPACITY = 512
GUARD_SIZE = 16
SOURCE_GUARD = 0xD7
OUTPUT_GUARD = 0xA5
OUTPUT_FILL = 0xCC
RETURN_ADDRESS = 0x00123456
IMPORT_IP = oracle.IMPORT_BASE + 42
EAX_SENTINEL = 0xAABBCCDD
FLAGS_SENTINEL = 0xCD5
LAST_ERROR_SENTINEL = 0x76543210
LCID_EN_US = 0x0409
CT_CTYPE1 = 1
LCMAP_LOWERCASE = 0x00000100
LCMAP_UPPERCASE = 0x00000200


def load_fixture() -> dict:
    with FIXTURE.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    if data.get("locale") != LCID_EN_US or data.get("codepage") != 1252:
        raise ValueError("Windows NLS fixture must describe en-US CP1252")
    if len(data.get("wide", ())) != 256 or data["wide"][0] != 0:
        raise ValueError("Windows NLS fixture must contain 256 decoded CP1252 units")
    for field in ("ctype_a", "ctype_w", "lower_a", "lower_w", "upper_a", "upper_w"):
        if len(data.get(field, ())) != 256:
            raise ValueError(f"Windows NLS fixture field {field} must have 256 values")
    return data


class NlsOracleRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = load_fixture()
        cls.input_a = bytes(range(256))
        cls.input_w = struct.pack("<256H", *cls.fixture["wide"])

    def setUp(self) -> None:
        self.engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        self.engine.mem_map(STACK_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(DATA_BASE, PAGE_SIZE, unicorn.UC_PROT_ALL)
        self.engine.mem_map(oracle.TEB_BASE, oracle.TEB_SIZE, unicorn.UC_PROT_ALL)
        self.mapped_ranges = [
            (STACK_BASE, STACK_BASE + PAGE_SIZE),
            (DATA_BASE, DATA_BASE + PAGE_SIZE),
            (oracle.TEB_BASE, oracle.TEB_BASE + oracle.TEB_SIZE),
        ]
        self._write_guarded_source(SRC_A, self.input_a)
        self._write_guarded_source(SRC_W, self.input_w)
        self._reset_output()
        self._set_last_error(LAST_ERROR_SENTINEL)

    def _write_guarded_source(self, address: int, content: bytes) -> None:
        guarded = (bytes([SOURCE_GUARD]) * GUARD_SIZE + content +
                   bytes([SOURCE_GUARD]) * GUARD_SIZE)
        self.engine.mem_write(address - GUARD_SIZE, guarded)

    def _assert_sources_unchanged(self) -> None:
        for address, content in ((SRC_A, self.input_a), (SRC_W, self.input_w)):
            expected = (bytes([SOURCE_GUARD]) * GUARD_SIZE + content +
                        bytes([SOURCE_GUARD]) * GUARD_SIZE)
            self.assertEqual(bytes(self.engine.mem_read(address - GUARD_SIZE,
                                                        len(expected))), expected)

    def _reset_output(self) -> None:
        self.engine.mem_write(
            OUT_BASE - GUARD_SIZE,
            bytes([OUTPUT_GUARD]) * GUARD_SIZE +
            bytes([OUTPUT_FILL]) * OUT_CAPACITY +
            bytes([OUTPUT_GUARD]) * GUARD_SIZE,
        )

    def _assert_output(self, expected: bytes | None) -> None:
        actual = bytes(self.engine.mem_read(OUT_BASE, OUT_CAPACITY))
        if expected is None:
            self.assertEqual(actual, bytes([OUTPUT_FILL]) * OUT_CAPACITY)
        else:
            self.assertEqual(actual[:len(expected)], expected)
            self.assertEqual(actual[len(expected):],
                             bytes([OUTPUT_FILL]) * (OUT_CAPACITY - len(expected)))
        self.assertEqual(
            bytes(self.engine.mem_read(OUT_BASE - GUARD_SIZE, GUARD_SIZE)),
            bytes([OUTPUT_GUARD]) * GUARD_SIZE,
        )
        self.assertEqual(
            bytes(self.engine.mem_read(OUT_BASE + OUT_CAPACITY, GUARD_SIZE)),
            bytes([OUTPUT_GUARD]) * GUARD_SIZE,
        )

    def _set_last_error(self, value: int) -> None:
        self.engine.mem_write(
            oracle.TEB_BASE + oracle.LAST_ERROR_OFFSET,
            struct.pack("<I", value),
        )

    def _last_error(self) -> int:
        return struct.unpack(
            "<I", self.engine.mem_read(
                oracle.TEB_BASE + oracle.LAST_ERROR_OFFSET, 4)
        )[0]

    def _call(self, name: str, arguments: tuple[int, ...], expected_result: int,
              expected_output: bytes | None, expected_outcome: str) -> None:
        functions = {
            "GetStringTypeA": oracle._get_string_type_a,
            "GetStringTypeW": oracle._get_string_type_w,
            "LCMapStringA": oracle._lc_map_string_a,
            "LCMapStringW": oracle._lc_map_string_w,
        }
        handler = functions[name]
        frame = struct.pack("<I" + "I" * len(arguments),
                            RETURN_ADDRESS, *arguments)
        self.engine.mem_write(STACK_BASE, frame)
        self._reset_output()
        self._set_last_error(LAST_ERROR_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_ESP, STACK_BASE)
        self.engine.reg_write(x86_const.UC_X86_REG_EIP, IMPORT_IP)
        self.engine.reg_write(x86_const.UC_X86_REG_EAX, EAX_SENTINEL)
        self.engine.reg_write(x86_const.UC_X86_REG_EBX, 0x11223344)
        self.engine.reg_write(x86_const.UC_X86_REG_ECX, 0x55667788)
        self.engine.reg_write(x86_const.UC_X86_REG_EDX, 0x99AABBCC)
        self.engine.reg_write(x86_const.UC_X86_REG_EBP, 0xDDEEFF00)
        self.engine.reg_write(x86_const.UC_X86_REG_ESI, 0x13579BDF)
        self.engine.reg_write(x86_const.UC_X86_REG_EDI, 0x2468ACE0)
        self.engine.reg_write(x86_const.UC_X86_REG_EFLAGS, FLAGS_SENTINEL)
        flags_before = (self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) &
                        oracle.EFLAGS_MASK)
        registers_before = {
            register: self.engine.reg_read(register)
            for register in (
                x86_const.UC_X86_REG_EBX, x86_const.UC_X86_REG_ECX,
                x86_const.UC_X86_REG_EDX, x86_const.UC_X86_REG_EBP,
                x86_const.UC_X86_REG_ESI, x86_const.UC_X86_REG_EDI,
            )
        }
        self.state = {
            "last_ip": IMPORT_IP,
            "api_calls": [],
            "resume": False,
            "status": None,
        }
        row = {"library": "KERNEL32.dll", "name": name, "index": 42}
        handled = handler(self.engine, x86_const, unicorn, row,
                          self.mapped_ranges, self.state)

        self.assertTrue(handled, f"{name} was not handled")
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EAX),
                         expected_result)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_EIP),
                         RETURN_ADDRESS)
        self.assertEqual(self.engine.reg_read(x86_const.UC_X86_REG_ESP),
                         STACK_BASE + len(frame))
        self.assertEqual(
            self.engine.reg_read(x86_const.UC_X86_REG_EFLAGS) & oracle.EFLAGS_MASK,
            flags_before,
        )
        for register, value in registers_before.items():
            self.assertEqual(self.engine.reg_read(register), value)
        self.assertEqual(self._last_error(), LAST_ERROR_SENTINEL)
        self.assertEqual(bytes(self.engine.mem_read(STACK_BASE, len(frame))), frame)
        self.assertEqual(self.state["api_calls"][-1]["outcome"], expected_outcome)
        self.assertEqual(self.state["api_calls"][-1]["result"], expected_result)
        self._assert_output(expected_output)
        self._assert_sources_unchanged()

    def test_get_string_type_a_matches_all_bytes_and_embedded_nul(self) -> None:
        expected = struct.pack("<256H", *self.fixture["ctype_a"])
        self._call("GetStringTypeA",
                   (LCID_EN_US, CT_CTYPE1, SRC_A, 256, OUT_BASE),
                   1, expected, "success")

    def test_get_string_type_w_matches_all_units_and_embedded_nul(self) -> None:
        expected = struct.pack("<256H", *self.fixture["ctype_w"])
        self._call("GetStringTypeW", (CT_CTYPE1, SRC_W, 256, OUT_BASE),
                   1, expected, "success")

    def _assert_map(self, name: str, flags: int, source: int, fixture_field: str,
                    wide: bool) -> None:
        query = (LCID_EN_US, flags, source, 256, OUT_BASE, 0)
        self._call(name, query, 256, None, "query_size")
        mapped = (LCID_EN_US, flags, source, 256, OUT_BASE, 256)
        values = self.fixture[fixture_field]
        expected = struct.pack("<256H", *values) if wide else bytes(values)
        self._call(name, mapped, 256, expected, "mapped")

    def test_lc_map_string_a_lower_upper_queries_and_outputs(self) -> None:
        self._assert_map("LCMapStringA", LCMAP_LOWERCASE, SRC_A,
                         "lower_a", wide=False)
        self._assert_map("LCMapStringA", LCMAP_UPPERCASE, SRC_A,
                         "upper_a", wide=False)

    def test_lc_map_string_w_lower_upper_queries_and_outputs(self) -> None:
        self._assert_map("LCMapStringW", LCMAP_LOWERCASE, SRC_W,
                         "lower_w", wide=True)
        self._assert_map("LCMapStringW", LCMAP_UPPERCASE, SRC_W,
                         "upper_w", wide=True)


if __name__ == "__main__":
    unittest.main()
