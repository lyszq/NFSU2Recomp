#!/usr/bin/env python3
"""Private bounded entry generation. No game input/output enters public CI."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
ENTRY = 0x0075BCC7
LEAF = 0x0048B1E0
SHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"


def generate(exe):
    import pefile
    sys.path.insert(0, str(ROOT / "tools"))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lift import Lifter, Unsupported
    from startup_oracle import run_startup_reference
    blob = exe.read_bytes()
    if len(blob) != 4788224 or hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError("unsupported executable")
    os.environ["FLAGOPT"] = "0"
    os.environ["RETEIP"] = "1"
    os.environ.pop("FLAGABI", None)
    os.environ.pop("X87OPT", None)

    class StartupLifter(Lifter):
        def discover(self, entry, maxins=512):
            blocks, calls = super().discover(entry, maxins=maxins)
            if len(blocks) > 256 or sum(len(b) for b in blocks.values()) > 2048:
                raise Unsupported("bounded startup generation limit")
            return blocks, calls

        def insn(self, instruction, targets):
            # Desktop no-ops or helpers that would falsely continue are explicit
            # probe stops. Direct g_mem/string operations need a future checked
            # implementation; typed MR* access below already has full checks.
            if instruction.mnemonic in ("int3", "int", "hlt", "ud2", "retf", "cpuid", "rdtsc"):
                return [f'guest_execution_unsupported(c,0x{instruction.address:x}u,"probe boundary");']
            lines = super().insn(instruction, targets)
            if any("g_mem" in line or "rdtsc_shim" in line or "cpuid_shim" in line for line in lines):
                return [f'guest_execution_unsupported(c,0x{instruction.address:x}u,"unchecked bulk operation");']
            return lines

    pe = pefile.PE(data=blob)
    imports = [{"iat": entry.address, "library": descriptor.dll.decode("ascii"),
                "name": entry.name.decode("ascii") if entry.name else f"#{entry.ordinal}"}
               for descriptor in pe.DIRECTORY_ENTRY_IMPORT for entry in descriptor.imports]
    reference = run_startup_reference(exe, imports)
    if (reference["import_name"] != "TlsAlloc" or reference["instructions"] != 1115
            or reference["api_call_count"] != 18 or reference["critical_section_count"] != 14):
        raise ValueError("unexpected independent x86 entry boundary")
    # Prioritize the authentic observed startup path within the bounded static
    # graph. This changes generation order, never the guest instructions or API
    # outcomes. Missing/unliftable executed functions must fail generation.
    observed = list(dict.fromkeys(call["target"] for call in reference["direct_calls"]))
    queue = collections.deque([ENTRY] + observed)
    seen = set()
    bodies, omitted = {}, []
    lifter = StartupLifter(str(exe), comments=False, trap=False)
    while queue and len(bodies) < 64:
        address = queue.popleft()
        if address in seen or address == LEAF:
            continue
        seen.add(address)
        if not lifter.in_text(address):
            continue
        try:
            blocks, _ = lifter.discover(address)
            lifter.hooks = {i.address for block in blocks.values() for i in block}
            body, targets = lifter.lift(address)
            if lifter.truncated:
                raise Unsupported("incomplete control flow")
        except Unsupported:
            omitted.append(f"{address:08x}")
            continue  # Never register a synthetic success stub.
        body = re.sub(r"\bsub_([0-9a-f]{8})\(c\)",
                      lambda m: f"guest_execution_call(c,0x{m.group(1)}u)", body)
        body = body.replace("dispatch_indirect(", "guest_execution_call(")
        body = body.replace("guest_hook(", "guest_execution_step(")
        body = body.replace("unsupported_insn(", "guest_execution_unsupported(")
        bodies[address] = body
        queue.extend(t for t in sorted(targets) if lifter.in_text(t) and t not in seen)
    if ENTRY not in bodies or not all(a in bodies for a in [0x00760DA0, 0x0075C4D0]):
        raise ValueError("authentic entry prefix is not completely lifted")
    if any(address not in bodies and address != LEAF for address in observed):
        raise ValueError("an executed startup function was not statically lifted")
    output = ROOT / "gen/ios-private"
    if not (output / "manifest.json").is_file():
        raise ValueError("generate the leaf regression first")
    # Preserve upstream CPU ABI, but check every generated typed access. RW is
    # intentional: probe image/stack pages are RW, never executable host pages.
    prefix = '#include "guest_execution.h"\n'
    for macro, typ, width in [("MR8", "uint8_t", 1), ("MR16", "uint16_t", 2),
                              ("MR32", "uint32_t", 4), ("MR64", "uint64_t", 8),
                              ("MRF32", "float", 4), ("MRF64", "double", 8)]:
        prefix += f"#undef {macro}\n#define {macro}(a) (*({typ}*)guest_execution_pointer((uint32_t)(a),{width}u))\n"
    prefix += 'void sub_0048b1e0(CPU *c);\n'
    content = prefix + "\n".join(bodies[a] for a in sorted(bodies))
    addresses = sorted(set(bodies) | {LEAF})
    content += "\nconst uint32_t nfs_startup_addresses[] = {" + ",".join(f"0x{a:08x}u" for a in addresses) + "};\n"
    content += "const GuestFunction nfs_startup_functions[] = {" + ",".join(f"sub_{a:08x}" for a in addresses) + "};\n"
    content += f"const uint32_t nfs_startup_count = {len(addresses)}u;\n"
    content += "const GuestImport nfs_startup_imports[] = {\n" + ",\n".join(
        "{" + f"0x{i['iat']:08x}u," + json.dumps(i["library"]) + "," + json.dumps(i["name"]) + "}"
        for i in imports) + "};\n"
    content += f"const uint32_t nfs_startup_import_count = {len(imports)}u;\n"
    (output / "startup_lifted.c").write_text(content, encoding="utf-8", newline="\n")
    harness = (ROOT / "tools/ios_private/startup_probe.c.in").read_text(encoding="utf-8")
    substitutions = {"EXPECTED_GPRS": ",".join(f"0x{x:08x}u" for x in reference["cpu"]["r"]),
                     "EXPECTED_FLAGS": f"0x{reference['cpu']['eflags_masked']:x}u",
                     "EXPECTED_TARGET": f"0x{reference['target']:08x}u",
                     "EXPECTED_IP": f"0x{reference['ip']:08x}u",
                     "EXPECTED_STEPS": str(reference["instructions"]),
                     "EXPECTED_APIS": str(reference["api_call_count"]),
                     "EXPECTED_CRITICALS": str(reference["critical_section_count"]),
                     "EXPECTED_CALLS": str(reference["calls"]),
                     "EXPECTED_DEPTH": str(reference["maximum_depth"]),
                     "EXPECTED_TRACE": str(reference["trace_hash"]),
                     "EXPECTED_IMAGE_HASH": str(reference["image_hash64"]),
                     "EXPECTED_TEB_HASH": str(reference["teb_hash64"]),
                     "EXPECTED_STACK_HASH": str(reference["stack_hash64"]),
                     "EXPECTED_HEAP_HASH": str(reference["heap_hash64"]),
                     "HEAP_WINDOW_ADDRESS": f"0x{reference['heap_hash_start']:08x}u",
                     "HEAP_WINDOW_SIZE": str(reference["heap_hash_size"]),
                     "STACK_WINDOW_ADDRESS": f"0x{reference['stack_hash_start']:08x}u",
                     "STACK_WINDOW_SIZE": str(reference["stack_hash_size"])}
    for key, value in substitutions.items():
        harness = harness.replace("@" + key + "@", value)
    if re.search(r"@[A-Z_]+@", harness):
        raise ValueError("unresolved native probe template")
    (output / "startup_probe.c").write_text(harness, encoding="utf-8", newline="\n")
    (output / "decls.h").write_text('#include "cpu.h"\nvoid sub_0075bcc7(CPU*);\n', encoding="utf-8")
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    manifest["startup"] = {"entry": f"{ENTRY:08x}", "generated_functions": len(addresses),
                            "unliftable_omitted": omitted, "frontier_remaining": len(queue),
                            "import_count": len(imports), "reference": reference,
                            "semantics": "original x86 instructions with explicit XP/module/heap/critical-section contracts; strict stop at unimplemented APIs"}
    for name in ["startup_lifted.c", "startup_probe.c"]:
        manifest[name + "_sha256"] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"PASS | private static entry generation | {len(addresses)} functions | {len(imports)} imports | "
          f"x86 reference stops before {reference['import_name']} after {reference['instructions']} instructions | "
          f"{reference['api_call_count']} implemented API calls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    generate(parser.parse_args().exe)
