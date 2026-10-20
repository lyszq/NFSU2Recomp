#!/usr/bin/env python3
"""Build-host x86 reference for the authenticated, bounded startup prefix.

This module executes the original PE instructions in Unicorn only up to the
first tagged import.  It never supplies an API result and never writes game
bytes or generated C.  Its result is intended to be compared with the native
statically lifted startup probe.
"""
from __future__ import annotations

from pathlib import Path
import struct
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DEPS = ROOT / "out" / "private-deps"
if PRIVATE_DEPS.is_dir():
    sys.path.insert(0, str(PRIVATE_DEPS))

SUPPORTED_EXE_SIZE = 4_788_224
SUPPORTED_EXE_SHA256 = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"
IMAGE_BASE = 0x00400000
ENTRY_POINT = 0x0075BCC7
IMPORT_BASE = 0xF0000000
TEB_BASE = 0x00C00000
PEB_BASE = 0x00C10000
TEB_SIZE = 0x20000
STACK_LO = 0x7F000000
STACK_HI = 0x7FF00000
STACK_SIZE = STACK_HI - STACK_LO
INITIAL_ESP = STACK_HI - 0x1000
ENTRY_RETURN = 0xDEADC0DE
EFLAGS_INITIAL = 0x202
EFLAGS_MASK = 0xCD5
FCW_INITIAL = 0x037F
FNV64_OFFSET = 14695981039346656037
FNV64_PRIME = 1099511628211
FNV64_MASK = 0xFFFFFFFFFFFFFFFF
INSTRUCTION_BUDGET = 100_000
STACK_WINDOW_BELOW = 0x1000
STACK_WINDOW_SIZE = 0x2000


def _fnv1a64(data: bytes | bytearray | memoryview) -> int:
    value = FNV64_OFFSET
    for byte in memoryview(data).cast("B"):
        value = ((value ^ byte) * FNV64_PRIME) & FNV64_MASK
    return value


def _read_u32(engine: Any, address: int) -> int:
    return struct.unpack("<I", engine.mem_read(address, 4))[0]


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", "replace")
    return str(value)


def _import_fields(item: Any) -> tuple[int, str, str]:
    """Accept the generator's dict rows, GuestImport-like objects, or triples."""
    if isinstance(item, Mapping):
        iat = item.get("iat", item.get("iat_address", item.get("address")))
        library = item.get("library", item.get("dll"))
        name = item.get("name", item.get("symbol"))
    elif isinstance(item, (tuple, list)) and len(item) == 3:
        iat, library, name = item
    else:
        iat = getattr(item, "iat", getattr(item, "iat_address", None))
        library = getattr(item, "library", getattr(item, "dll", None))
        name = getattr(item, "name", getattr(item, "symbol", None))
    if iat is None or library is None or name is None:
        raise ValueError("each import must provide iat, library, and name")
    address = int(iat)
    if not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("import IAT address is outside PE32 address space")
    return address, _as_text(library), _as_text(name)


def _pe_imports(pe: Any) -> list[tuple[int, str, str]]:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        raise ValueError("the executable has no parsed import table")
    rows = []
    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        library = descriptor.dll.decode("ascii", "replace")
        for imported in descriptor.imports:
            name = (imported.name.decode("ascii", "replace") if imported.name
                    else f"#{imported.ordinal}")
            rows.append((int(imported.address), library, name))
    return rows


def _validate_imports(pe_rows: list[tuple[int, str, str]], supplied: list[Any]) -> list[dict[str, Any]]:
    rows = [_import_fields(item) for item in supplied]
    if len(rows) != len(pe_rows):
        raise ValueError(f"import list is incomplete: PE={len(pe_rows)} supplied={len(rows)}")
    expected = {iat: (library.casefold(), name) for iat, library, name in pe_rows}
    if len(expected) != len(pe_rows):
        raise ValueError("PE import table contains duplicate IAT addresses")
    seen: set[int] = set()
    normalized = []
    for index, (iat, library, name) in enumerate(rows):
        if iat in seen:
            raise ValueError(f"duplicate IAT address in import list: 0x{iat:08x}")
        seen.add(iat)
        if expected.get(iat) != (library.casefold(), name):
            raise ValueError(f"import metadata does not match PE at IAT 0x{iat:08x}")
        normalized.append({"index": index, "iat": iat, "library": library, "name": name})
    if seen != set(expected):
        raise ValueError("import list does not cover the PE import table")
    return normalized


def _loader_image(pe: Any, blob: bytes) -> bytearray:
    """Mirror runtime/guest_pe.c: zero SizeOfImage, copy headers, then min(raw, VS)."""
    size = int(pe.OPTIONAL_HEADER.SizeOfImage)
    headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if not size or size > 64 * 1024 * 1024 or not headers or headers > size or headers > len(blob):
        raise ValueError("PE image/header sizes are outside the native loader limits")
    image = bytearray(size)
    image[:headers] = blob[:headers]
    for section in pe.sections:
        virtual_size = int(section.Misc_VirtualSize) or int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        raw_offset = int(section.PointerToRawData)
        copied = min(virtual_size, raw_size)
        if (virtual_address > size or virtual_size > size - virtual_address or
                raw_offset > len(blob) or copied > len(blob) - raw_offset):
            raise ValueError("PE section bounds disagree with the native loader")
        if copied:
            image[virtual_address:virtual_address + copied] = blob[raw_offset:raw_offset + copied]
    return image


def _segment_descriptor(base: int, access: int) -> bytes:
    limit = 0xFFFFF
    return struct.pack(
        "<HHBBBB",
        limit & 0xFFFF,
        base & 0xFFFF,
        (base >> 16) & 0xFF,
        access,
        ((limit >> 16) & 0x0F) | 0xC0,  # page granularity, 32-bit segment
        (base >> 24) & 0xFF,
    )


def _register_id(registers: Any, name: str) -> int:
    mapping = {
        "eax": registers.UC_X86_REG_EAX,
        "ecx": registers.UC_X86_REG_ECX,
        "edx": registers.UC_X86_REG_EDX,
        "ebx": registers.UC_X86_REG_EBX,
        "esp": registers.UC_X86_REG_ESP,
        "ebp": registers.UC_X86_REG_EBP,
        "esi": registers.UC_X86_REG_ESI,
        "edi": registers.UC_X86_REG_EDI,
    }
    return mapping[name]


def run_startup_reference(exe: Path, imports: list) -> dict[str, Any]:
    """Run the exact PE entry only until its first bound import thunk.

    `imports` is the same ordered list passed to the native IAT binder.  Each
    row can be a mapping with `iat`/`library`/`name`, an object with those
    attributes, or a three-item `(iat, library, name)` tuple.  The returned
    status must be `GUEST_STOP_IMPORT`; other stops raise so a changed startup
    path cannot silently become a successful oracle.
    """
    try:
        import pefile
        import unicorn as uc
        from unicorn import x86_const as xr
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError as exc:  # pragma: no cover - build host dependency failure
        raise RuntimeError("startup oracle requires build-host pefile, Capstone, and Unicorn") from exc

    path = Path(exe)
    blob = path.read_bytes()
    import hashlib
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != SUPPORTED_EXE_SIZE or digest != SUPPORTED_EXE_SHA256:
        raise ValueError("unsupported executable; startup oracle did not run")
    pe = pefile.PE(data=blob, fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if image_base != IMAGE_BASE or entry != ENTRY_POINT or int(pe.FILE_HEADER.Machine) != 0x14C:
        raise ValueError("authenticated executable layout changed")

    pe_rows = _pe_imports(pe)
    import_rows = _validate_imports(pe_rows, imports)
    index_by_iat = {row["iat"]: row["index"] for row in import_rows}
    first_expected = next((row for row in import_rows
                           if row["iat"] == 0x00783168), None)
    if not first_expected or first_expected["library"].casefold() != "kernel32.dll" or first_expected["name"] != "GetVersionExA":
        raise ValueError("the first startup import is not the expected GetVersionExA slot")

    image = _loader_image(pe, blob)
    image_size = len(image)
    page_size = 0x1000
    map_size = (image_size + page_size - 1) & ~(page_size - 1)
    engine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
    engine.mem_map(image_base, map_size, uc.UC_PROT_ALL)
    engine.mem_write(image_base, bytes(image))
    engine.mem_map(TEB_BASE, TEB_SIZE, uc.UC_PROT_ALL)
    engine.mem_map(STACK_LO, STACK_SIZE, uc.UC_PROT_ALL)
    # The import tags are executable stop sentinels. Unicorn requests a code
    # page before issuing its code hook, so map their page as inert zeroes.
    # The hook stops at the tag before any byte in this page is executed.
    engine.mem_map(IMPORT_BASE, page_size, uc.UC_PROT_ALL)

    # Unicorn does not provide a usable FS_BASE register in 32-bit mode.
    # Install flat 32-bit GDT segments so actual FS:[0] accesses reach the TEB.
    gdt_base = 0x10000000
    engine.mem_map(gdt_base, page_size, uc.UC_PROT_ALL)
    engine.mem_write(gdt_base + 8, _segment_descriptor(0, 0x9A))
    engine.mem_write(gdt_base + 16, _segment_descriptor(0, 0x92))
    engine.mem_write(gdt_base + 24, _segment_descriptor(TEB_BASE, 0x92))
    engine.reg_write(xr.UC_X86_REG_GDTR, (0, gdt_base, 0x1F, 0))
    for register, selector in (
        (xr.UC_X86_REG_CS, 0x08),
        (xr.UC_X86_REG_SS, 0x10),
        (xr.UC_X86_REG_DS, 0x10),
        (xr.UC_X86_REG_ES, 0x10),
        (xr.UC_X86_REG_FS, 0x18),
        (xr.UC_X86_REG_GS, 0x18),
    ):
        engine.reg_write(register, selector)

    # Match tests/boot.c. The PEB is inside this zeroed 0x20000-byte region.
    teb = bytearray(TEB_SIZE)
    for address, value in (
        (0x00, 0xFFFFFFFF),
        (0x04, STACK_HI),
        (0x08, STACK_LO),
        (0x18, TEB_BASE),
        (0x20, 100),
        (0x24, 1),
        (0x2C, TEB_BASE + 0x1000),
        (0x30, PEB_BASE),
        (PEB_BASE - TEB_BASE + 0x08, image_base),
        (PEB_BASE - TEB_BASE + 0xA4, 5),
        (PEB_BASE - TEB_BASE + 0xA8, 1),
    ):
        struct.pack_into("<I", teb, address, value)
    engine.mem_write(TEB_BASE, bytes(teb))

    # The native loader starts with zeroed committed pages and the same return
    # sentinel that tests/boot.c pushes before calling the entry function.
    start_esp = INITIAL_ESP - 4
    engine.mem_write(start_esp, struct.pack("<I", ENTRY_RETURN))
    engine.reg_write(xr.UC_X86_REG_ESP, start_esp)
    engine.reg_write(xr.UC_X86_REG_EBP, 0)
    engine.reg_write(xr.UC_X86_REG_EFLAGS, EFLAGS_INITIAL)
    if hasattr(xr, "UC_X86_REG_FPCW"):
        engine.reg_write(xr.UC_X86_REG_FPCW, FCW_INITIAL)
    engine.reg_write(xr.UC_X86_REG_EIP, entry)

    # Bind every import to the exact sentinel/index order used by native code.
    for row in import_rows:
        sentinel = IMPORT_BASE + row["index"]
        if sentinel > 0xFFFFFFFF:
            raise ValueError("import sentinel overflows PE32 address space")
        image_offset = row["iat"] - image_base
        if image_offset < 0 or image_offset + 4 > image_size:
            raise ValueError(f"IAT is outside the mapped image: 0x{row['iat']:08x}")
        struct.pack_into("<I", image, image_offset, sentinel)
        engine.mem_write(row["iat"], struct.pack("<I", sentinel))

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    state: dict[str, Any] = {
        "status": None,
        "last_ip": 0,
        "instructions": 0,
        "calls": 1,  # guest_execution_run dispatches the entry function itself.
        "depth": 1,
        "maximum_depth": 1,
        "trace_hash": FNV64_OFFSET,
        "direct_calls": [],
        "import": None,
        "memory_fault": None,
    }

    def stop_at_import(address: int) -> bool:
        if address < IMPORT_BASE:
            return False
        index = address - IMPORT_BASE
        if index >= len(import_rows):
            state["status"] = "GUEST_STOP_UNRESOLVED"
            state["target"] = address
        else:
            row = import_rows[index]
            state["status"] = "GUEST_STOP_IMPORT"
            state["target"] = address
            state["import_index"] = index
            state["import"] = dict(row)
        engine.emu_stop()
        return True

    regids = {name: _register_id(xr, name) for name in
              ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")}

    def on_code(uc_engine: Any, address: int, size: int, user_data: Any) -> None:
        if stop_at_import(address):
            return
        if state["instructions"] >= INSTRUCTION_BUDGET:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = address
            engine.emu_stop()
            return
        try:
            instruction = next(md.disasm(bytes(uc_engine.mem_read(address, min(size, 15))), address), None)
        except Exception:
            instruction = None
        if instruction is None:
            state["status"] = "GUEST_STOP_INSTRUCTION"
            state["target"] = address
            engine.emu_stop()
            return

        state["last_ip"] = int(address) & 0xFFFFFFFF
        state["instructions"] += 1
        state["trace_hash"] = ((state["trace_hash"] ^ state["last_ip"]) * FNV64_PRIME) & FNV64_MASK

        if instruction.mnemonic == "call" and instruction.operands:
            state["calls"] += 1
            operand = instruction.operands[0]
            target = None
            if operand.type == X86_OP_IMM:
                target = int(operand.imm) & 0xFFFFFFFF
            elif operand.type == X86_OP_REG:
                target = int(uc_engine.reg_read(regids[instruction.reg_name(operand.reg)])) & 0xFFFFFFFF
            elif operand.type == X86_OP_MEM:
                memory = operand.mem
                effective = int(memory.disp) & 0xFFFFFFFF
                if memory.base:
                    effective = (effective + int(uc_engine.reg_read(regids[instruction.reg_name(memory.base)]))) & 0xFFFFFFFF
                if memory.index:
                    effective = (effective + int(uc_engine.reg_read(regids[instruction.reg_name(memory.index)])) * int(memory.scale)) & 0xFFFFFFFF
                segment = instruction.reg_name(memory.segment) if memory.segment else ""
                if segment == "fs":
                    effective = (effective + TEB_BASE) & 0xFFFFFFFF
                elif segment == "gs":
                    effective = (effective + TEB_BASE) & 0xFFFFFFFF
                try:
                    target = _read_u32(uc_engine, effective)
                except Exception:
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = effective
                    engine.emu_stop()
                    return
            if target is not None and target < IMPORT_BASE and IMAGE_BASE <= target < IMAGE_BASE + image_size:
                state["direct_calls"].append({"ip": int(address), "target": target})
                state["depth"] += 1
                state["maximum_depth"] = max(state["maximum_depth"], state["depth"])
            elif target is not None and target >= IMPORT_BASE:
                # The actual CALL executes after this hook and pushes its return
                # address. The code hook at the tagged destination stops before
                # any API body can run.
                state["pending_import_target"] = target

        if instruction.mnemonic in ("ret", "retf") and state["depth"] > 1:
            state["depth"] -= 1

    def on_unmapped(uc_engine: Any, access: int, address: int, size: int,
                    value: int, user_data: Any) -> bool:
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {"access": int(access), "address": int(address), "size": int(size)}
        engine.emu_stop()
        return False

    engine.hook_add(uc.UC_HOOK_CODE, on_code)
    engine.hook_add(uc.UC_HOOK_MEM_UNMAPPED, on_unmapped)
    try:
        engine.emu_start(entry, 0, count=INSTRUCTION_BUDGET + 1)
    except Exception as exc:
        if state["status"] is None:
            state["status"] = "GUEST_STOP_MEMORY"
            state["target"] = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
            state["emulator_error"] = f"{type(exc).__name__}: {exc}"

    if state["status"] != "GUEST_STOP_IMPORT":
        raise RuntimeError(f"startup oracle stopped at {state.get('status')} target=0x{state.get('target', 0):08x}")
    first = state["import"]
    if first["iat"] != 0x00783168 or first["name"] != "GetVersionExA":
        raise RuntimeError("startup oracle reached an unexpected first import")

    # The guest runner's EIP is the last instruction reported by its step hook;
    # Unicorn's architectural EIP is the tagged import target after CALL.
    gprs = {name: int(engine.reg_read(registers)) & 0xFFFFFFFF
            for name, registers in regids.items()}
    architectural_eip = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
    eflags = int(engine.reg_read(xr.UC_X86_REG_EFLAGS)) & EFLAGS_MASK
    gprs["esp"] = int(engine.reg_read(xr.UC_X86_REG_ESP)) & 0xFFFFFFFF
    last_ip = state["last_ip"]
    stack_hash_start = max(STACK_LO, gprs["esp"] - STACK_WINDOW_BELOW)
    stack_hash_end = min(STACK_HI, stack_hash_start + STACK_WINDOW_SIZE)
    stack_window = bytes(engine.mem_read(stack_hash_start, stack_hash_end - stack_hash_start))
    image_state = bytes(engine.mem_read(image_base, image_size))
    teb_state = bytes(engine.mem_read(TEB_BASE, TEB_SIZE))

    flags = {
        "cf": eflags & 0x001,
        "pf": (eflags >> 2) & 1,
        "af": (eflags >> 4) & 1,
        "zf": (eflags >> 6) & 1,
        "sf": (eflags >> 7) & 1,
        "df": (eflags >> 10) & 1,
        "of": (eflags >> 11) & 1,
    }
    cpu_state = {
        "r": [gprs[name] for name in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")],
        "gpr": gprs,
        "eip": last_ip,
        "fs_base": TEB_BASE,
        "gs_base": TEB_BASE,
        "eflags_masked": eflags,
        "flags": flags,
        "fcw": FCW_INITIAL,
        "fsw": 0,
        "top": 0,
        "st_f64_bits": [0] * 8,
        "mm": [0] * 8,
        "xmm_u64": [[0, 0] for _ in range(8)],
    }
    result = {
        "schema_version": 1,
        "reference": "Unicorn x86-32; authentic PE instructions through first import; no API body executed",
        "executable_size": len(blob),
        "executable_sha256": digest,
        "image_base": image_base,
        "image_size": image_size,
        "entry_point": entry,
        "status": state["status"],
        "ip": last_ip,
        "target": int(state["target"]),
        "import_index": int(state["import_index"]),
        "import_iat": int(first["iat"]),
        "import_library": first["library"],
        "import_name": first["name"],
        "instructions": int(state["instructions"]),
        "calls": int(state["calls"]),
        "maximum_depth": int(state["maximum_depth"]),
        "trace_hash": int(state["trace_hash"]),
        "cpu": cpu_state,
        "unicorn_eip_at_stop": architectural_eip,
        "direct_calls": state["direct_calls"],
        "image_hash_start": image_base,
        "image_hash_size": image_size,
        "image_hash64": _fnv1a64(image_state),
        "teb_hash_start": TEB_BASE,
        "teb_hash_size": TEB_SIZE,
        "teb_hash64": _fnv1a64(teb_state),
        "stack_hash_start": stack_hash_start,
        "stack_hash_size": len(stack_window),
        "stack_hash64": _fnv1a64(stack_window),
        "stack_base": STACK_LO,
        "stack_size": STACK_SIZE,
        "stack_initial_esp": start_esp,
    }
    return result
