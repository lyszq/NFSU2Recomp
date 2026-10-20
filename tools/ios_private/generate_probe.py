#!/usr/bin/env python3
"""Privately lift one authenticated game function and derive an x86 oracle.

Outputs contain game-derived C: only use ignored gen/ios-private. Never print
or publish these outputs. Unicorn is a build-host reference, not the iOS runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
EXE_SHA = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"
FUNCTION = 0x0048B1E0  # Existing upstream tests/main_all.c contract.
STACK = 0x00E00000
ESP = STACK + 0x8000
RETURN = 0x0F000000


def generate(exe, output):
    import pefile
    import unicorn as uc
    from unicorn import x86_const as xr
    sys.path.insert(0, str(ROOT / "tools"))
    os.environ["FLAGOPT"] = "0"
    os.environ["RETEIP"] = "1"
    os.environ.pop("FLAGABI", None)
    os.environ.pop("X87OPT", None)
    from lift import Lifter

    blob = exe.read_bytes()
    if len(blob) != 4788224 or hashlib.sha256(blob).hexdigest() != EXE_SHA:
        raise ValueError("unsupported executable; nothing generated")
    allowed = ROOT / "gen" / "ios-private"
    if output.resolve() != allowed.resolve():
        raise ValueError("output must be the ignored repository gen/ios-private directory")
    lifter = Lifter(str(exe), comments=False, trap=False)
    blocks, calls = lifter.discover(FUNCTION)
    instructions = [i for block in blocks.values() for i in block]
    if calls or len(instructions) != 7 or sum(i.size for i in instructions) != 16:
        raise ValueError("audited leaf-function shape changed")
    lifted, targets = lifter.lift(FUNCTION)
    if targets or lifter.truncated or "unsupported_insn" in lifted:
        raise ValueError("function requires unsupported dispatch or truncated code")
    pe = pefile.PE(data=blob)
    offset = pe.get_offset_from_rva(FUNCTION - pe.OPTIONAL_HEADER.ImageBase)
    code = blob[offset:offset + 16]
    registers = [xr.UC_X86_REG_EAX, xr.UC_X86_REG_ECX, xr.UC_X86_REG_EDX,
                 xr.UC_X86_REG_EBX, xr.UC_X86_REG_ESP, xr.UC_X86_REG_EBP,
                 xr.UC_X86_REG_ESI, xr.UC_X86_REG_EDI]
    arguments = [0, 1, 2, 4, 7, 100, 255, 65535, 0x7FFFFFFF, 0x80000000,
                 0xFFFFFFFE, 0xFFFFFFFF]
    vectors = []
    for argument in arguments:
        for flags in [0x202, 0x247, 0xA92, 0xED7]:
            engine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
            engine.mem_map(FUNCTION & ~0xFFF, 0x1000)
            engine.mem_write(FUNCTION, code)
            engine.mem_map(STACK, 0x10000)
            engine.mem_map(RETURN, 0x1000)
            before = [0xFEEDCAFE, 0x12345678, 0x98765432, 0xABCDEFA1,
                      ESP, 0x12345000, 0x10203040, 0x50607080]
            for register, value in zip(registers, before):
                engine.reg_write(register, value)
            engine.reg_write(xr.UC_X86_REG_EFLAGS, flags)
            engine.mem_write(ESP, struct.pack("<II", RETURN, argument))
            engine.emu_start(FUNCTION, RETURN, count=100)
            after = [engine.reg_read(register) for register in registers]
            eip = engine.reg_read(xr.UC_X86_REG_EIP)
            after_flags = engine.reg_read(xr.UC_X86_REG_EFLAGS) & 0xCD5
            if eip != RETURN or after[0] != (0x832DE0 + argument * 0x70) & 0xFFFFFFFF:
                raise ValueError("x86 oracle disagrees with upstream function contract")
            if after[4] != ESP + 4 or after[5] != before[5]:
                raise ValueError("x86 oracle violated cdecl stack contract")
            stack = list(engine.mem_read(ESP - 16, 32))
            vectors.append((argument, flags, before, after, eip, after_flags, stack))
    output.mkdir(parents=True, exist_ok=True)
    (output / "lifted.c").write_text('#include "cpu.h"\n' + lifted + '\n')
    rows = []
    for arg, flags, before, after, eip, expected_flags, stack in vectors:
        words = lambda values: ",".join(f"0x{v:08x}u" for v in values)
        rows.append("{" + f"0x{arg:08x}u,0x{flags:x}u," + "{" + words(before) + "},{" +
                    words(after) + "}," + f"0x{eip:x}u,0x{expected_flags:x}u," +
                    "{" + ",".join(str(v) for v in stack) + "}}")
    harness = r'''
#include "cpu.h"
#include "guest_memory.h"
#include <errno.h>
#include <stdio.h>
void sub_0048b1e0(CPU *c);
typedef struct {
    uint32_t argument, flags, before[8], after[8], eip, after_flags;
    uint8_t stack[32];
} Vector;
static const Vector vectors[] = { VECTORS };
int nfs_private_lifted_probe(char *out, size_t capacity) {
    int rc = guest_memory_commit(0x00e00000u, 0x10000u);
    if (rc) {
        (void)snprintf(out, capacity, "FAIL | private lifted stack commit | error=%d", rc);
        return rc;
    }
    for (unsigned i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
        const Vector *v = &vectors[i];
        CPU c = {0};
        memcpy(c.r, v->before, sizeof c.r);
        eflags_set(&c, v->flags);
        memset(g_mem + 0x00e07ff0u, 0, 32);
        MR32(c.esp) = 0x0f000000u;
        MR32(c.esp + 4u) = v->argument;
        sub_0048b1e0(&c); /* Actual statically recompiled game function. */
        if (memcmp(c.r, v->after, sizeof c.r) || c.eip != v->eip ||
            (eflags_get(&c) & 0xcd5u) != v->after_flags ||
            memcmp(g_mem + 0x00e07ff0u, v->stack, 32)) {
            (void)snprintf(out, capacity, "FAIL | actual lifted sub_0048b1e0 | x86 reference case=%u", i);
            return EINVAL;
        }
    }
    (void)snprintf(out, capacity,
        "PASS | actual statically lifted sub_0048b1e0 | 48 x86 reference cases | "
        "GPR + EFLAGS + return + stack match | no JIT | no game boot");
    return 0;
}
'''.replace("VECTORS", ",\n".join(rows))
    (output / "private_probe.c").write_text(harness)
    manifest = {"executable_sha256": EXE_SHA, "function_va": f"{FUNCTION:08x}",
                "instruction_count": 7, "function_bytes": 16,
                "function_sha256": hashlib.sha256(code).hexdigest(),
                "reference": f"Unicorn {uc.__version__} x86-32 (build host only)",
                "vectors": len(vectors), "runtime_jit": False}
    for name in ["lifted.c", "private_probe.c"]:
        manifest[name + "_sha256"] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("PASS | authenticated private generation | function=0048b1e0 | 48 x86 oracle cases")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "gen" / "ios-private")
    args = parser.parse_args()
    generate(args.exe, args.output)
