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


def observed_startup_targets(reference):
    """CALL entries and dynamic JMP entries, never invented dispatch stubs."""
    transfers = reference["direct_calls"] + reference["indirect_jumps"]
    return list(dict.fromkeys(event["target"] for event in transfers))


def startup_lifter_class(Lifter, Unsupported):
    """Create the bounded lifter without opening a proprietary input."""
    class StartupLifter(Lifter):
        def tail_dispatch(self, expression):
            return f"guest_execution_tail(c, {expression}); return;"

        def discover(self, entry, maxins=512):
            blocks, calls = super().discover(entry, maxins=maxins)
            if len(blocks) > 256 or sum(len(b) for b in blocks.values()) > 2048:
                raise Unsupported("bounded startup generation limit")
            return blocks, calls

        def insn(self, instruction, targets):
            if instruction.mnemonic == "cpuid":
                return [f'if (!guest_cpuid(c)) guest_execution_unsupported(c,0x{instruction.address:x}u,"unsupported CPUID leaf");']
            if instruction.mnemonic == "rdtsc":
                return ["guest_execution_rdtsc(c);"]
            # Desktop no-ops or helpers that would falsely continue are explicit
            # probe stops. Direct g_mem/string operations need a future checked
            # implementation; typed MR* access below already has full checks.
            if instruction.mnemonic in ("int3", "int", "hlt", "ud2", "retf"):
                return [f'guest_execution_unsupported(c,0x{instruction.address:x}u,"probe boundary");']
            lines = super().insn(instruction, targets)
            if any("g_mem" in line or "rdtsc_shim" in line or "cpuid_shim" in line for line in lines):
                return [f'guest_execution_unsupported(c,0x{instruction.address:x}u,"unchecked bulk operation");']
            return lines

    return StartupLifter


def generate(exe):
    sys.path.insert(0, str(ROOT / "out" / "private-deps"))
    sys.path.insert(0, str(ROOT / "tools"))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import pefile
    from lift import Lifter, Unsupported
    from startup_oracle import run_startup_reference
    blob = exe.read_bytes()
    if len(blob) != 4788224 or hashlib.sha256(blob).hexdigest() != SHA256:
        raise ValueError("unsupported executable")
    os.environ["FLAGOPT"] = "0"
    os.environ["RETEIP"] = "1"
    os.environ.pop("FLAGABI", None)
    os.environ.pop("X87OPT", None)
    StartupLifter = startup_lifter_class(Lifter, Unsupported)

    pe = pefile.PE(data=blob)
    imports = [{"iat": entry.address, "library": descriptor.dll.decode("ascii"),
                "name": entry.name.decode("ascii") if entry.name else f"#{entry.ordinal}"}
               for descriptor in pe.DIRECTORY_ENTRY_IMPORT for entry in descriptor.imports]
    reference = run_startup_reference(exe, imports, diagnostic_directory=ROOT / "gen/ios-private")
    # Registry, CPU capability, cursor and window contracts advance
    # the explicit fixture prefix to its CreateToolhelp32Snapshot query. Native comparisons stay exact.
    if (reference["import_name"] != "CreateToolhelp32Snapshot" or reference["raw_instructions"] != 217254
            or reference["calls"] != 10482 or reference["api_call_count"] != 865
            or reference["critical_section_count"] != 14
            or reference["tls_slot_count"] != 1 or reference["tls_thread_count"] != 1):
        raise ValueError(f"unexpected independent x86 entry boundary: {reference['import_name']} {reference['instructions']}")
    # Prioritize the authentic observed startup path within the bounded static
    # graph. This changes generation order, never the guest instructions or API
    # outcomes. Missing/unliftable executed functions must fail generation.
    observed = observed_startup_targets(reference)
    queue = collections.deque([ENTRY] + observed)
    seen = set()
    bodies, omitted = {}, []
    lifter = StartupLifter(str(exe), comments=False, trap=False)
    while queue and len(bodies) < 1200:
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
        raise ValueError("executed targets not lifted: " + ",".join(f"{a:08x}" for a in observed if a not in bodies and a != LEAF))
    output = ROOT / "gen/ios-private"
    if not (output / "manifest.json").is_file():
        raise ValueError("generate the leaf regression first")
    # Preserve upstream CPU ABI, but check every generated typed access. RW is
    # intentional: probe image/stack pages are RW, never executable host pages.
    prefix = '#include "guest_execution.h"\n#include "guest_cpuid.h"\n'
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
    user_objects = [[0] * 6 for _ in range(8)]
    for handle, obj in reference["user_objects"].items():
        slot = int(handle) - 0x00b10001
        if not 0 <= slot < 8 or obj != {"handle": int(handle), "kind": "CURSOR", "origin": "SYSTEM_SHARED",
                "system_id": 32512, "module": 0, "shared": True}:
            raise ValueError("unexpected USER32 object profile")
        user_objects[slot] = [int(handle), 2, 2, 0, 32512, 1]
    substitutions = {"EXPECTED_TSC_NEXT": str(reference["virtual_tsc_next"]),
                     "EXPECTED_TSC_READS": str(len(reference["rdtsc_calls"])),
                     "EXPECTED_TSC_HASH": str(reference["virtual_tsc_hash"]),
                     "EXPECTED_USER_OBJECT_COUNT": str(len(reference["user_objects"])),
                     "EXPECTED_USER_OBJECTS": ",".join("{"+",".join(str(x)+"u" for x in row)+"}" for row in user_objects),
                     "EXPECTED_GPRS": ",".join(f"0x{x:08x}u" for x in reference["cpu"]["r"]),
                     "EXPECTED_FLAGS": f"0x{reference['cpu']['eflags_masked']:x}u",
                     "EXPECTED_TARGET": f"0x{reference['target']:08x}u",
                     "EXPECTED_IP": f"0x{reference['ip']:08x}u",
                     "EXPECTED_STEPS": str(reference["instructions"]),
                     "EXPECTED_APIS": str(reference["api_call_count"]),
                     "EXPECTED_CRITICALS": str(reference["critical_section_count"]),
                     "EXPECTED_TLS": str(reference["tls_slot_count"]),
                     "EXPECTED_TLS_THREADS": str(reference["tls_thread_count"]),
                     "EXPECTED_ENV_A_REFS": str(reference["process_state"]["environment_a_refs"]),
                     "EXPECTED_ENV_W_REFS": str(reference["process_state"]["environment_w_refs"]),
                     "EXPECTED_HEAPS": ",".join("{"+",".join(str(v)+"u" for v in
                         (h["slot"],h["handle"],h["capacity"],int(h["fixed"])))+"}"
                         for h in reference["state_heaps"] if h["handle"]),
                     "EXPECTED_BLOCKS": ",".join("{"+",".join(str(v)+"u" for v in
                         (h["slot"],b["slot"],b["address"],b["size"],b["span"]))+"}"
                         for h in reference["state_heaps"] for b in h["blocks"]),
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
                     "STACK_WINDOW_SIZE": str(reference["stack_hash_size"]),
                     "PROCESS_WINDOW_ADDRESS": f"0x{reference['process_hash_start']:08x}u",
                     "PROCESS_WINDOW_SIZE": str(reference["process_hash_size"]),
                     "EXPECTED_PROCESS_HASH": str(reference["process_hash64"])}
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
                            "semantics": "original x86 instructions with explicit XP/module/heap/critical/TLS/thread-identity/process/stdio contracts; strict stop at unimplemented APIs"}
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
