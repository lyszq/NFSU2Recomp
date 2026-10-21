"""Run the native guest locale handlers against a captured Windows NLS table."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "windows_nls_cp1252.json"


def c_array(name: str, c_type: str, values: list[int], digits: int) -> str:
    rows = []
    for start in range(0, len(values), 12):
        row = values[start:start + 12]
        rows.append("    " + ", ".join(f"0x{value:0{digits}x}u" for value in row))
    return f"static const {c_type} {name}[256] = {{\n" + ",\n".join(rows) + "\n};"


NATIVE_TEST = r'''#include "guest_bootstrap.h"
#include "guest_locale.h"
#include "guest_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    STACK_BASE = 0x00100000u,
    DATA_BASE = 0x00200000u,
    SOURCE_GUARD = 16u,
    SRC_A = DATA_BASE + 0x100u,
    SRC_W = DATA_BASE + 0x400u,
    OUT_BASE = DATA_BASE + 0x900u,
    OUT_CAPACITY = 512u,
    OUTPUT_GUARD = 16u,
    IMPORT_IP = 0xf0000042u,
    RETURN_IP = 0x00123456u,
    EAX_SENTINEL = 0xaabbccddu,
    EBX_SENTINEL = 0x11223344u,
    ECX_SENTINEL = 0x55667788u,
    EDX_SENTINEL = 0x99aabbccu,
    EBP_SENTINEL = 0xddeeff00u,
    ESI_SENTINEL = 0x13579bdfu,
    EDI_SENTINEL = 0x2468ace0u,
    FLAGS_CF = 1u,
    FLAGS_PF = 0u,
    FLAGS_AF = 1u,
    FLAGS_ZF = 0u,
    FLAGS_SF = 1u,
    FLAGS_OF = 1u,
    FLAGS_DF = 0u,
    LAST_ERROR_SENTINEL = 0x76543210u,
    FAULT_SENTINEL = 0xdeadbeefu,
    LCID_EN_US = 0x0409u,
    CT_CTYPE1 = 1u,
    LCMAP_LOWERCASE = 0x00000100u,
    LCMAP_UPPERCASE = 0x00000200u,
    GUARD_BYTE = 0xa5u,
    OUTPUT_FILL = 0xccu,
    SOURCE_GUARD_BYTE = 0xd7u
};

@@ARRAYS@@

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
        puts("FAIL guest locale Windows NLS CP1252"); \
        return 1; \
    } \
} while (0)

static uint8_t input_a[256];

static void set_last_error(uint32_t value) {
    memcpy(g_mem + GUEST_TEB_BASE + 0x34u, &value, sizeof value);
}

static uint32_t get_last_error(void) {
    uint32_t value;
    memcpy(&value, g_mem + GUEST_TEB_BASE + 0x34u, sizeof value);
    return value;
}

static void reset_output(void) {
    memset(g_mem + OUT_BASE - OUTPUT_GUARD, GUARD_BYTE, OUTPUT_GUARD);
    memset(g_mem + OUT_BASE, OUTPUT_FILL, OUT_CAPACITY);
    memset(g_mem + OUT_BASE + OUT_CAPACITY, GUARD_BYTE, OUTPUT_GUARD);
}

static int output_guards_ok(void) {
    for (uint32_t i = 0; i < OUTPUT_GUARD; ++i) {
        if (g_mem[OUT_BASE - OUTPUT_GUARD + i] != GUARD_BYTE ||
            g_mem[OUT_BASE + OUT_CAPACITY + i] != GUARD_BYTE) return 0;
    }
    return 1;
}

static int output_matches(const void *expected, size_t expected_size) {
    if (expected_size && memcmp(g_mem + OUT_BASE, expected, expected_size) != 0) return 0;
    for (size_t i = expected_size; i < OUT_CAPACITY; ++i) {
        if (g_mem[OUT_BASE + i] != OUTPUT_FILL) return 0;
    }
    return output_guards_ok();
}

static int input_guards_ok(void) {
    for (uint32_t i = 0; i < SOURCE_GUARD; ++i) {
        if (g_mem[SRC_A - SOURCE_GUARD + i] != SOURCE_GUARD_BYTE ||
            g_mem[SRC_A + 256u + i] != SOURCE_GUARD_BYTE ||
            g_mem[SRC_W - SOURCE_GUARD + i] != SOURCE_GUARD_BYTE ||
            g_mem[SRC_W + 512u + i] != SOURCE_GUARD_BYTE) return 0;
    }
    return memcmp(g_mem + SRC_A, input_a, sizeof input_a) == 0 &&
           memcmp(g_mem + SRC_W, nls_wide, sizeof nls_wide) == 0;
}

static void initialize_sources(void) {
    for (uint32_t i = 0; i < 256u; ++i) input_a[i] = (uint8_t)i;
    memset(g_mem + SRC_A - SOURCE_GUARD, SOURCE_GUARD_BYTE, SOURCE_GUARD);
    memcpy(g_mem + SRC_A, input_a, sizeof input_a);
    memset(g_mem + SRC_A + sizeof input_a, SOURCE_GUARD_BYTE, SOURCE_GUARD);
    memset(g_mem + SRC_W - SOURCE_GUARD, SOURCE_GUARD_BYTE, SOURCE_GUARD);
    memcpy(g_mem + SRC_W, nls_wide, sizeof nls_wide);
    memset(g_mem + SRC_W + sizeof nls_wide, SOURCE_GUARD_BYTE, SOURCE_GUARD);
}

static int flags_unchanged(const CPU *cpu) {
    return cpu->cf == FLAGS_CF && cpu->pf == FLAGS_PF &&
           cpu->af == FLAGS_AF && cpu->zf == FLAGS_ZF &&
           cpu->sf == FLAGS_SF && cpu->of == FLAGS_OF &&
           cpu->df == FLAGS_DF;
}

static int run_import(const char *name, const uint32_t *arguments,
                      uint32_t argument_count, uint32_t expected_eax,
                      const void *expected_output, size_t expected_output_size) {
    CPU cpu;
    GuestImport import = { 0u, "KERNEL32.dll", name };
    uint32_t frame[7] = { 0 };
    uint32_t frame_bytes = (argument_count + 1u) * 4u;
    uint32_t fault = FAULT_SENTINEL;

    if (argument_count > 6u) return 1;
    frame[0] = RETURN_IP;
    memcpy(frame + 1, arguments, argument_count * sizeof(uint32_t));
    memcpy(g_mem + STACK_BASE, frame, frame_bytes);
    reset_output();
    set_last_error(LAST_ERROR_SENTINEL);

    memset(&cpu, 0, sizeof cpu);
    cpu.esp = STACK_BASE;
    cpu.eip = IMPORT_IP;
    cpu.eax = EAX_SENTINEL;
    cpu.ebx = EBX_SENTINEL;
    cpu.ecx = ECX_SENTINEL;
    cpu.edx = EDX_SENTINEL;
    cpu.ebp = EBP_SENTINEL;
    cpu.esi = ESI_SENTINEL;
    cpu.edi = EDI_SENTINEL;
    cpu.fs_base = GUEST_TEB_BASE;
    cpu.cf = FLAGS_CF;
    cpu.pf = FLAGS_PF;
    cpu.af = FLAGS_AF;
    cpu.zf = FLAGS_ZF;
    cpu.sf = FLAGS_SF;
    cpu.of = FLAGS_OF;
    cpu.df = FLAGS_DF;

    CHECK(guest_locale_import(&cpu, &import, &fault) == 1,
          "supported locale import succeeds");
    CHECK(cpu.eax == expected_eax, "locale import returns the captured Windows count/result");
    CHECK(cpu.eip == RETURN_IP && cpu.esp == STACK_BASE + frame_bytes,
          "locale import performs the expected stdcall return");
    CHECK(cpu.ebx == EBX_SENTINEL && cpu.ecx == ECX_SENTINEL &&
          cpu.edx == EDX_SENTINEL && cpu.ebp == EBP_SENTINEL &&
          cpu.esi == ESI_SENTINEL && cpu.edi == EDI_SENTINEL,
          "locale import preserves non-result general registers");
    CHECK(flags_unchanged(&cpu), "locale import preserves x86 flags");
    CHECK(fault == FAULT_SENTINEL, "successful locale import leaves fault output untouched");
    CHECK(get_last_error() == LAST_ERROR_SENTINEL,
          "successful locale import preserves TEB LastError");
    CHECK(memcmp(g_mem + STACK_BASE, frame, frame_bytes) == 0,
          "locale import leaves its explicit-count stdcall frame unchanged");
    CHECK(output_matches(expected_output, expected_output_size),
          "locale output matches Windows data and stays inside its guards");
    CHECK(input_guards_ok(), "locale import preserves all 256 source values and guards");
    return 0;
}

static int test_get_string_type(void) {
    uint32_t args_a[] = { LCID_EN_US, CT_CTYPE1, SRC_A, 256u, OUT_BASE };
    uint32_t args_w[] = { CT_CTYPE1, SRC_W, 256u, OUT_BASE };
    CHECK(run_import("GetStringTypeA", args_a, 5u, 1u,
                     nls_ctype_a, sizeof nls_ctype_a) == 0,
          "GetStringTypeA matches all 256 Windows CP1252 byte classifications");
    CHECK(run_import("GetStringTypeW", args_w, 4u, 1u,
                     nls_ctype_w, sizeof nls_ctype_w) == 0,
          "GetStringTypeW matches all 256 Windows UTF-16 classifications");
    return 0;
}

static int test_lc_map_string_a(void) {
    const uint32_t flags[] = { LCMAP_LOWERCASE, LCMAP_UPPERCASE };
    const uint8_t *expected[] = { nls_lower_a, nls_upper_a };
    const char *names[] = { "LCMapStringA lower", "LCMapStringA upper" };
    for (uint32_t i = 0; i < 2u; ++i) {
        uint32_t query[] = { LCID_EN_US, flags[i], SRC_A, 256u, OUT_BASE, 0u };
        uint32_t mapped[] = { LCID_EN_US, flags[i], SRC_A, 256u, OUT_BASE, 256u };
        CHECK(run_import("LCMapStringA", query, 6u, 256u, NULL, 0u) == 0,
              names[i]);
        CHECK(run_import("LCMapStringA", mapped, 6u, 256u,
                         expected[i], 256u) == 0,
              names[i]);
    }
    return 0;
}

static int test_lc_map_string_w(void) {
    const uint32_t flags[] = { LCMAP_LOWERCASE, LCMAP_UPPERCASE };
    const uint16_t *expected[] = { nls_lower_w, nls_upper_w };
    const char *names[] = { "LCMapStringW lower", "LCMapStringW upper" };
    for (uint32_t i = 0; i < 2u; ++i) {
        uint32_t query[] = { LCID_EN_US, flags[i], SRC_W, 256u, OUT_BASE, 0u };
        uint32_t mapped[] = { LCID_EN_US, flags[i], SRC_W, 256u, OUT_BASE, 256u };
        CHECK(run_import("LCMapStringW", query, 6u, 256u, NULL, 0u) == 0,
              names[i]);
        CHECK(run_import("LCMapStringW", mapped, 6u, 256u,
                         expected[i], sizeof nls_lower_w) == 0,
              names[i]);
    }
    return 0;
}

int main(void) {
    CHECK(guest_memory_init() == 0, "synthetic guest memory initializes");
    CHECK(guest_memory_commit(STACK_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic stdcall stack commits RW");
    CHECK(guest_memory_commit(DATA_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic source/output area commits RW");
    CHECK(guest_memory_commit(GUEST_TEB_BASE, GUEST_MEMORY_GRANULE) == 0,
          "synthetic TEB commits RW");
    initialize_sources();
    CHECK(nls_wide[0] == 0u && input_a[0] == 0u,
          "fixture input explicitly contains its embedded NUL");
    CHECK(test_get_string_type() == 0, "GetStringTypeA/W pass");
    CHECK(test_lc_map_string_a() == 0, "LCMapStringA query/mapping pass");
    CHECK(test_lc_map_string_w() == 0, "LCMapStringW query/mapping pass");
    CHECK(guest_memory_shutdown() == 0, "synthetic guest memory shuts down");
    puts("PASS guest locale Windows NLS CP1252");
    return 0;
}
'''


class GuestLocaleWindowsRegressionTests(unittest.TestCase):
    def test_native_handlers_match_all_windows_cp1252_values(self) -> None:
        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("clang is required to build the native guest locale probe")
        with FIXTURE.open("r", encoding="utf-8") as stream:
            fixture = json.load(stream)

        self.assertEqual(fixture.get("locale"), 0x0409)
        self.assertEqual(fixture.get("codepage"), 1252)
        self.assertEqual(len(fixture.get("wide", ())), 256)
        self.assertEqual(fixture["wide"][0], 0)
        array_specs = (
            ("nls_wide", "uint16_t", "wide", 4),
            ("nls_ctype_a", "uint16_t", "ctype_a", 4),
            ("nls_ctype_w", "uint16_t", "ctype_w", 4),
            ("nls_lower_a", "uint8_t", "lower_a", 2),
            ("nls_lower_w", "uint16_t", "lower_w", 4),
            ("nls_upper_a", "uint8_t", "upper_a", 2),
            ("nls_upper_w", "uint16_t", "upper_w", 4),
        )
        arrays = []
        for c_name, c_type, fixture_name, digits in array_specs:
            values = fixture[fixture_name]
            self.assertEqual(len(values), 256, fixture_name)
            max_value = 0xff if c_type == "uint8_t" else 0xffff
            self.assertTrue(all(isinstance(value, int) and 0 <= value <= max_value
                                for value in values), fixture_name)
            arrays.append(c_array(c_name, c_type, values, digits))
        source = NATIVE_TEST.replace("@@ARRAYS@@", "\n\n".join(arrays))

        with tempfile.TemporaryDirectory(prefix="guest-locale-nls-") as temp_name:
            temp = Path(temp_name)
            c_path = temp / "guest_locale_nls.c"
            executable = temp / "guest_locale_nls"
            c_path.write_text(source, encoding="utf-8")
            command = [
                clang, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                "-pthread", "-I", str(ROOT / "runtime"), str(c_path),
                str(ROOT / "runtime" / "guest_memory.c"),
                str(ROOT / "runtime" / "guest_locale.c"), "-o", str(executable),
            ]
            compiled = subprocess.run(command, cwd=ROOT, text=True,
                                      capture_output=True, timeout=60, check=False)
            self.assertEqual(compiled.returncode, 0,
                             f"clang failed:\n{compiled.stdout}\n{compiled.stderr}")
            result = subprocess.run([str(executable)], cwd=ROOT, text=True,
                                    capture_output=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 0,
                             f"native NLS probe failed:\n{result.stdout}\n{result.stderr}")
            self.assertIn("PASS guest locale Windows NLS CP1252", result.stdout)


if __name__ == "__main__":
    unittest.main()
