#!/usr/bin/env python3
"""Capture synthetic CP1252 contracts from Windows, without any game input."""
import argparse
import ctypes as c
import json
from pathlib import Path
import sys


def capture():
    if sys.platform != "win32":
        raise RuntimeError("This reference capture requires real Windows APIs")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.MultiByteToWideChar.argtypes = [c.c_uint, c.c_uint, c.c_char_p, c.c_int, c.c_void_p, c.c_int]
    kernel.GetStringTypeW.argtypes = [c.c_uint, c.c_void_p, c.c_int, c.c_void_p]
    kernel.GetStringTypeA.argtypes = [c.c_uint, c.c_uint, c.c_char_p, c.c_int, c.c_void_p]
    kernel.LCMapStringW.argtypes = [c.c_uint, c.c_uint, c.c_void_p, c.c_int, c.c_void_p, c.c_int]
    kernel.LCMapStringA.argtypes = [c.c_uint, c.c_uint, c.c_char_p, c.c_int, c.c_void_p, c.c_int]
    raw = bytes(range(256))
    wide = (c.c_uint16 * 256)()
    assert kernel.MultiByteToWideChar(1252, 0, raw, 256, wide, 256) == 256
    ctype_a, ctype_w = (c.c_uint16 * 256)(), (c.c_uint16 * 256)()
    assert kernel.GetStringTypeA(0x409, 1, raw, 256, ctype_a)
    assert kernel.GetStringTypeW(1, wide, 256, ctype_w)
    result = {"schema": 1, "source": "Direct Windows kernel32 API execution; synthetic bytes 0..255",
              "windows_version": list(sys.getwindowsversion()[:3]), "locale": 0x409,
              "codepage": 1252, "wide": list(wide), "ctype_a": list(ctype_a), "ctype_w": list(ctype_w)}
    for label, flags in (("lower", 0x100), ("upper", 0x200)):
        dst_w, dst_a = (c.c_uint16 * 512)(), (c.c_ubyte * 512)()
        size_w = kernel.LCMapStringW(0x409, flags, wide, 256, None, 0)
        size_a = kernel.LCMapStringA(0x409, flags, raw, 256, None, 0)
        assert kernel.LCMapStringW(0x409, flags, wide, 256, dst_w, 512) == size_w == 256
        assert kernel.LCMapStringA(0x409, flags, raw, 256, dst_a, 512) == size_a == 256
        result[label + "_w"] = list(dst_w)[:size_w]
        result[label + "_a"] = list(dst_a)[:size_a]
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(capture(), indent=2) + "\n", encoding="utf-8")
    print("PASS | Windows NLS capture | 256 synthetic CP1252 inputs | ANSI/Unicode type and case maps")
