#!/usr/bin/env python3
"""Downstream reverse engineering exploration script for SPEED2.EXE.

Simulates execution through Unicorn with toolhelp APIs and LastError handled,
tracing execution flow after 0x005b7b30 succeeds until the next unsupported import or instruction.
"""
from __future__ import annotations

import collections
import hashlib
from pathlib import Path
import struct
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DEPS = ROOT / "out" / "private-deps"
TOOLS = ROOT / "tools"
IOS_PRIVATE = TOOLS / "ios_private"

for p in (PRIVATE_DEPS, TOOLS, IOS_PRIVATE):
    if p.is_dir() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pefile
import unicorn as uc
from unicorn import x86_const as xr
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

import startup_oracle as so
from registry_oracle import _registry_import
from window_oracle import _window_query_import
from resource_oracle import _resource_import
from metrics_oracle import apply_metrics
from cursor_oracle import _cursor_query_import
from tsc_oracle import apply_rdtsc
from cpuid_oracle import apply_cpuid
from generate_startup import observed_startup_targets


CUSTOM_ARGUMENT_COUNTS = {
    "CreateToolhelp32Snapshot": 2,
    "Process32First": 2,
    "Process32Next": 2,
    "CloseHandle": 1,
    "GetLastError": 0,
    "SetLastError": 1,
    "QueryPerformanceFrequency": 1,
    "GetCurrentProcess": 0,
    "GetCurrentThread": 0,
    "DuplicateHandle": 7,
    "timeGetDevCaps": 2,
}

ALL_BOUNDARY_ARGUMENT_COUNTS = dict(so.BOUNDARY_ARGUMENT_COUNTS)
ALL_BOUNDARY_ARGUMENT_COUNTS.update(CUSTOM_ARGUMENT_COUNTS)


def run_downstream_exploration(exe_path: Path, max_budget: int = 5_000_000,
                               stage: int = 0):
    """Run exploration.
    stage -1: Toolhelp intercepted, but GetLastError NOT handled (strictly unmodified imports).
    stage 0: Toolhelp + GetLastError/SetLastError handled -> reaches QueryPerformanceFrequency.
    stage 1: Also handles QueryPerformanceFrequency -> reaches GetCurrentProcess.
    stage 2: Also handles GetCurrentProcess/Thread/DuplicateHandle -> reaches timeGetDevCaps.
    """
    blob = exe_path.read_bytes()
    pe = pefile.PE(data=blob, fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    pe_rows = so._pe_imports(pe)
    imports_list = [{"iat": entry.address, "library": descriptor.dll.decode("ascii"),
                     "name": entry.name.decode("ascii") if entry.name else f"#{entry.ordinal}"}
                    for descriptor in pe.DIRECTORY_ENTRY_IMPORT for entry in descriptor.imports]
    import_rows = so._validate_imports(pe_rows, imports_list)

    image = so._loader_image(pe, blob)
    image_size = len(image)

    group_icon_types = [t for t in pe.DIRECTORY_ENTRY_RESOURCE.entries if t.id == 14]
    missing_application_icon = (len(group_icon_types) == 1 and
        all(n.id != 32512 for n in group_icon_types[0].directory.entries))
    page_size = 0x1000
    map_size = (image_size + page_size - 1) & ~(page_size - 1)

    engine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
    engine.mem_map(image_base, map_size, uc.UC_PROT_ALL)
    engine.mem_write(image_base, bytes(image))
    engine.mem_map(so.TEB_BASE, so.TEB_SIZE, uc.UC_PROT_ALL)
    engine.mem_map(so.STACK_LO, so.STACK_SIZE, uc.UC_PROT_ALL)
    engine.mem_map(so.IMPORT_BASE, page_size, uc.UC_PROT_ALL)

    # GDT setup
    gdt_base = 0x10000000
    engine.mem_map(gdt_base, page_size, uc.UC_PROT_ALL)
    engine.mem_write(gdt_base + 8, so._segment_descriptor(0, 0x9A))
    engine.mem_write(gdt_base + 16, so._segment_descriptor(0, 0x92))
    engine.mem_write(gdt_base + 24, so._segment_descriptor(so.TEB_BASE, 0x92))
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

    teb = bytearray(so.TEB_SIZE)
    for address, value in (
        (0x00, 0xFFFFFFFF),
        (0x04, so.STACK_HI),
        (0x08, so.STACK_LO),
        (0x18, so.TEB_BASE),
        (0x20, 100),
        (0x24, 1),
        (0x2C, so.TEB_BASE + 0x1000),
        (0x30, so.PEB_BASE),
        (so.PEB_BASE - so.TEB_BASE + 0x08, image_base),
        (so.PEB_BASE - so.TEB_BASE + 0xA4, 5),
        (so.PEB_BASE - so.TEB_BASE + 0xA8, 1),
    ):
        struct.pack_into("<I", teb, address, value)
    engine.mem_write(so.TEB_BASE, bytes(teb))

    process_state = so._initialize_process_arena(engine, image_base, image_size, uc)

    start_esp = so.INITIAL_ESP - 4
    engine.mem_write(start_esp, struct.pack("<I", so.ENTRY_RETURN))
    engine.reg_write(xr.UC_X86_REG_ESP, start_esp)
    engine.reg_write(xr.UC_X86_REG_EBP, 0)
    engine.reg_write(xr.UC_X86_REG_EFLAGS, so.EFLAGS_INITIAL)
    if hasattr(xr, "UC_X86_REG_FPCW"):
        engine.reg_write(xr.UC_X86_REG_FPCW, so.FCW_INITIAL)
    engine.reg_write(xr.UC_X86_REG_EIP, entry)

    for row in import_rows:
        sentinel = so.IMPORT_BASE + row["index"]
        image_offset = row["iat"] - image_base
        struct.pack_into("<I", image, image_offset, sentinel)
        engine.mem_write(row["iat"], struct.pack("<I", sentinel))

    mapped_ranges = [
        (image_base, image_base + image_size),
        (so.TEB_BASE, so.TEB_BASE + so.TEB_SIZE),
        (so.PROCESS_BASE, so.PROCESS_BASE + so.PROCESS_COMMITTED_SIZE),
        (so.STACK_LO, so.STACK_HI),
    ]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    toolhelp_state = {
        "snapshot_handle": 0xCAFE0001,
        "first_called": False,
        "next_count": 0,
        "closed": False,
    }

    state: dict[str, Any] = {
        "status": None,
        "last_ip": 0,
        "instructions": 0,
        "calls": 1,
        "depth": 1,
        "maximum_depth": 1,
        "trace_hash": so.FNV64_OFFSET,
        "raw_instructions": 0,
        "raw_trace_hash": so.FNV64_OFFSET,
        "direct_calls": [],
        "indirect_jumps": [],
        "cpuid_calls": [],
        "virtual_tsc_next": 1000000,
        "virtual_tsc_increment": 1000,
        "rdtsc_calls": [],
        "virtual_tsc_hash": so.FNV64_OFFSET,
        "user_objects": {},
        "resource_image_base": image_base,
        "resource_missing_application_icon": missing_application_icon,
        "cursor_coords": (320, 180),
        "cursor_available": True,
        "cursor_profile": "deterministic_cursor_fixture_v1",
        "import": None,
        "api_calls": [],
        "boundary_call": None,
        "heaps": {},
        "critical_sections": {},
        "tls_allocated_bitmap": 0,
        "tls_slot_count": 0,
        "tls_threads": {so.TEB_BASE: 1},
        "tls_current_teb": so.TEB_BASE,
        "process": process_state,
        "unhandled_exception_filter": 0,
        "resume": False,
        "memory_fault": None,
        "executed_subroutines": collections.defaultdict(int),
        "subroutine_log": [],
        "call_stack": [entry],
    }

    def _handle_custom_import(name: str, esp: int, row: dict[str, Any]) -> bool:
        ret_addr = so._read_u32(engine, esp)
        if name == "CreateToolhelp32Snapshot":
            dwFlags = so._read_u32(engine, esp + 4)
            th32ProcessID = so._read_u32(engine, esp + 8)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 2,
                "arguments": [dwFlags, th32ProcessID], "result": toolhelp_state["snapshot_handle"],
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, toolhelp_state["snapshot_handle"])
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 12)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "Process32First":
            hSnapshot = so._read_u32(engine, esp + 4)
            lppe = so._read_u32(engine, esp + 8)
            toolhelp_state["first_called"] = True
            exe_name = b"speed2.exe\x00"
            engine.mem_write(lppe + 36, exe_name)
            so._write_u32(engine, lppe + 8, 100)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 2,
                "arguments": [hSnapshot, lppe], "result": 1,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 1)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 12)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "Process32Next":
            hSnapshot = so._read_u32(engine, esp + 4)
            lppe = so._read_u32(engine, esp + 8)
            toolhelp_state["next_count"] += 1
            so._write_u32(engine, so.TEB_BASE + so.LAST_ERROR_OFFSET, 18)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 2,
                "arguments": [hSnapshot, lppe], "result": 0,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 0)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 12)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "CloseHandle":
            hObject = so._read_u32(engine, esp + 4)
            toolhelp_state["closed"] = True
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 1,
                "arguments": [hObject], "result": 1,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 1)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 8)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "GetLastError" and stage >= 0:
            val = so._read_u32(engine, so.TEB_BASE + so.LAST_ERROR_OFFSET)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 0,
                "arguments": [], "result": val,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, val)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 4)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "SetLastError" and stage >= 0:
            err = so._read_u32(engine, esp + 4)
            so._write_u32(engine, so.TEB_BASE + so.LAST_ERROR_OFFSET, err)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 1,
                "arguments": [err], "result": 0,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 8)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "QueryPerformanceFrequency" and stage >= 1:
            lpFreq = so._read_u32(engine, esp + 4)
            so._write_u32(engine, lpFreq, 1000000)
            so._write_u32(engine, lpFreq + 4, 0)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 1,
                "arguments": [lpFreq], "result": 1,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 1)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 8)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "GetCurrentProcess" and stage >= 2:
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 0,
                "arguments": [], "result": 0xFFFFFFFF,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 0xFFFFFFFF)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 4)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "GetCurrentThread" and stage >= 2:
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 0,
                "arguments": [], "result": 0xFFFFFFFE,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 0xFFFFFFFE)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 4)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        elif name == "DuplicateHandle" and stage >= 2:
            hSourceProc = so._read_u32(engine, esp + 4)
            hSource = so._read_u32(engine, esp + 8)
            hTargetProc = so._read_u32(engine, esp + 12)
            lpTarget = so._read_u32(engine, esp + 16)
            dwDesiredAccess = so._read_u32(engine, esp + 20)
            bInherit = so._read_u32(engine, esp + 24)
            dwOptions = so._read_u32(engine, esp + 28)
            so._write_u32(engine, lpTarget, 0x10000002)
            api = {
                "library": row["library"], "name": name, "import_index": row["index"],
                "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 7,
                "arguments": [hSourceProc, hSource, hTargetProc, lpTarget, dwDesiredAccess, bInherit, dwOptions],
                "result": 1,
            }
            state["api_calls"].append(api)
            engine.reg_write(xr.UC_X86_REG_EAX, 1)
            engine.reg_write(xr.UC_X86_REG_ESP, esp + 32)
            engine.reg_write(xr.UC_X86_REG_EIP, ret_addr)
            state["resume"] = True
            return True

        return False

    def stop_at_import(address: int) -> bool:
        if address < so.IMPORT_BASE:
            return False
        index = address - so.IMPORT_BASE
        if index >= len(import_rows):
            state["status"] = "GUEST_STOP_UNRESOLVED"
            state["target"] = address
            engine.emu_stop()
            return True

        row = import_rows[index]
        api_key = (row["library"].casefold(), row["name"])
        name = row["name"]
        esp = int(engine.reg_read(xr.UC_X86_REG_ESP)) & 0xFFFFFFFF

        handled_set = {"CreateToolhelp32Snapshot", "Process32First", "Process32Next", "CloseHandle"}
        if stage >= 0:
            handled_set.update({"GetLastError", "SetLastError"})
        if stage >= 1:
            handled_set.add("QueryPerformanceFrequency")
        if stage >= 2:
            handled_set.update({"GetCurrentProcess", "GetCurrentThread", "DuplicateHandle"})

        if name in handled_set:
            handled = _handle_custom_import(name, esp, row)
            if handled:
                engine.emu_stop()
                return True

        if api_key in so.SUPPORTED_IMPORTS:
            if name == "RegOpenKeyA":
                handled = _registry_import(engine, xr, uc, row, mapped_ranges, state)
            elif name in ("GetWindowRect", "GetClientRect"):
                handled = _window_query_import(engine, xr, uc, row, mapped_ranges, state)
            elif name in ("LoadIconA", "LoadCursorA"):
                handled = _resource_import(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetSystemMetrics":
                handled = apply_metrics(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetCursorPos":
                handled = _cursor_query_import(engine, xr, uc, row, mapped_ranges, state)
            elif name == "IsProcessorFeaturePresent":
                handled = so._is_processor_feature_present(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetVersionExA":
                handled = so._get_version_ex_a(engine, xr, row, mapped_ranges, state)
            elif name == "GetModuleHandleA":
                handled = so._get_module_handle_a(engine, xr, row, mapped_ranges, image_base, state)
            elif name == "GetStartupInfoA":
                handled = so._get_startup_info_a(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetStdHandle":
                handled = so._get_std_handle(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetFileType":
                handled = so._get_file_type(engine, xr, uc, row, mapped_ranges, state)
            elif name == "SetHandleCount":
                handled = so._set_handle_count(engine, xr, uc, row, mapped_ranges, state)
            elif name in so.PROCESS_CODE_PAGES or name == "GetCommandLineA" or name in so.PROCESS_IMPORTS:
                handled = so._guest_process_import(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetCurrentThreadId":
                handled = so._get_current_thread_id(engine, xr, uc, row, mapped_ranges, state)
            elif name in so.TLS_IMPORTS:
                handled = so._tls_import(engine, xr, uc, row, mapped_ranges, state)
            elif name in so.CRITICAL_SECTION_IMPORTS:
                handled = so._critical_section_import(engine, xr, row, mapped_ranges, state)
            elif name == "HeapCreate":
                handled = so._heap_create(engine, xr, uc, row, mapped_ranges, state)
            elif name == "HeapAlloc":
                handled = so._heap_alloc(engine, xr, uc, row, mapped_ranges, state)
            elif name == "HeapReAlloc":
                handled = so._heap_realloc(engine, xr, uc, row, mapped_ranges, state)
            elif name == "HeapFree":
                handled = so._heap_free(engine, xr, uc, row, mapped_ranges, state)
            elif name == "WideCharToMultiByte":
                handled = so._wide_char_to_multi_byte(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetCPInfo":
                handled = so._get_cp_info(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetModuleFileNameA":
                handled = so._get_module_file_name_a(engine, xr, uc, row, mapped_ranges, image_base, state)
            elif name == "GetStringTypeW":
                handled = so._get_string_type_w(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetStringTypeA":
                handled = so._get_string_type_a(engine, xr, uc, row, mapped_ranges, state)
            elif name == "LCMapStringW":
                handled = so._lc_map_string_w(engine, xr, uc, row, mapped_ranges, state)
            elif name == "LCMapStringA":
                handled = so._lc_map_string_a(engine, xr, uc, row, mapped_ranges, state)
            elif name == "MultiByteToWideChar":
                handled = so._multi_byte_to_wide_char(engine, xr, uc, row, mapped_ranges, state)
            elif name == "SetUnhandledExceptionFilter":
                handled = so._set_unhandled_exception_filter(engine, xr, uc, row, mapped_ranges, state)
            elif name == "HeapSize":
                handled = so._heap_size(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetSystemTimeAsFileTime":
                handled = so._get_system_time_as_file_time(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetCurrentProcessId":
                handled = so._get_current_process_id(engine, xr, uc, row, mapped_ranges, state)
            elif name == "GetTickCount":
                handled = so._get_tick_count(engine, xr, uc, row, mapped_ranges, state)
            elif name == "QueryPerformanceCounter":
                handled = so._query_performance_counter(engine, xr, uc, row, mapped_ranges, state)
            else:
                handled = False

            if handled or state["status"] is not None:
                engine.emu_stop()
                return True

        # Unsupported import
        state["status"] = "GUEST_STOP_IMPORT"
        state["target"] = address
        state["import_index"] = index
        state["import"] = dict(row)
        argc = ALL_BOUNDARY_ARGUMENT_COUNTS.get(row["name"], 4)
        ret_addr = so._read_u32(engine, esp)
        args = [so._read_u32(engine, esp + 4 * (i + 1)) for i in range(argc)]
        state["boundary_call"] = {
            "call_ip": state["last_ip"],
            "target": address,
            "import_index": index,
            "library": row["library"],
            "name": row["name"],
            "esp": esp,
            "return_address": ret_addr,
            "argument_count": argc,
            "arguments": args,
        }
        engine.emu_stop()
        return True

    regids = {name: so._register_id(xr, name) for name in
              ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")}

    def on_code(uc_engine: Any, address: int, size: int, user_data: Any) -> None:
        if stop_at_import(address):
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

        state["raw_instructions"] += 1
        state["raw_trace_hash"] = ((state["raw_trace_hash"] ^ address) * so.FNV64_PRIME) & so.FNV64_MASK
        if so._is_rep_continuation(state, address, instruction.mnemonic):
            return
        if state["instructions"] >= max_budget:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = address
            engine.emu_stop()
            return

        state["last_ip"] = int(address) & 0xFFFFFFFF
        state["instructions"] += 1
        state["trace_hash"] = ((state["trace_hash"] ^ state["last_ip"]) * so.FNV64_PRIME) & so.FNV64_MASK

        if instruction.mnemonic == "rdtsc":
            if apply_rdtsc(uc_engine, xr, address, instruction.size, state):
                event = state["rdtsc_calls"][-1]
                for word in (event["address"], event["value"]):
                    state["virtual_tsc_hash"] = ((state["virtual_tsc_hash"] ^ word) * so.FNV64_PRIME) & so.FNV64_MASK
            return

        if instruction.mnemonic == "cpuid":
            apply_cpuid(uc_engine, xr, address, instruction.size, state)
            return

        if instruction.mnemonic in ("call", "jmp") and instruction.operands:
            is_call = instruction.mnemonic == "call"
            if is_call:
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
                if segment in ("fs", "gs"):
                    effective = (effective + so.TEB_BASE) & 0xFFFFFFFF
                try:
                    target = so._read_u32(uc_engine, effective)
                except Exception:
                    state["status"] = "GUEST_STOP_MEMORY"
                    state["target"] = effective
                    engine.emu_stop()
                    return

            if target is not None and target < so.IMPORT_BASE and image_base <= target < image_base + image_size:
                event = {"ip": int(address), "target": target}
                if is_call:
                    state["direct_calls"].append(event)
                    state["depth"] += 1
                    state["maximum_depth"] = max(state["maximum_depth"], state["depth"])
                    state["executed_subroutines"][target] += 1
                    state["subroutine_log"].append((target, address))
                    state["call_stack"].append(target)
                elif operand.type != X86_OP_IMM and event not in state["indirect_jumps"]:
                    state["indirect_jumps"].append(event)
            elif target is not None and target >= so.IMPORT_BASE:
                state["pending_import_target"] = target

        if instruction.mnemonic in ("ret", "retf"):
            if state["depth"] > 1:
                state["depth"] -= 1
            if len(state["call_stack"]) > 1:
                state["call_stack"].pop()

    def on_unmapped(uc_engine: Any, access: int, address: int, size: int,
                    value: int, user_data: Any) -> bool:
        state["status"] = "GUEST_STOP_MEMORY"
        state["target"] = int(address) & 0xFFFFFFFF
        state["memory_fault"] = {"access": int(access), "address": int(address), "size": int(size)}
        engine.emu_stop()
        return False

    engine.hook_add(uc.UC_HOOK_CODE, on_code)
    engine.hook_add(uc.UC_HOOK_MEM_UNMAPPED, on_unmapped)

    begin = entry
    while state["status"] is None:
        remaining = max_budget - state["instructions"] + 1
        state["resume"] = False
        try:
            engine.emu_start(begin, 0, count=remaining)
        except Exception as exc:
            if state["status"] is None:
                state["status"] = "GUEST_STOP_MEMORY"
                state["target"] = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
                state["emulator_error"] = f"{type(exc).__name__}: {exc}"
            break
        if state["status"] is not None:
            break
        if not state["resume"]:
            state["status"] = "GUEST_STOP_BUDGET"
            state["target"] = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF
            break
        begin = int(engine.reg_read(xr.UC_X86_REG_EIP)) & 0xFFFFFFFF

    return state, engine, import_rows


def print_stage_report(title: str, state: dict, engine: Any):
    targets = observed_startup_targets(state)
    bc = state["boundary_call"]
    gprs = {reg: engine.reg_read(getattr(xr, f"UC_X86_REG_{reg.upper()}")) for reg in ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]}
    eflags = engine.reg_read(xr.UC_X86_REG_EFLAGS)

    print(f"=== {title} ===")
    print(f"Status: {state['status']}")
    if bc:
        print(f"Boundary API: {bc['library']}!{bc['name']}")
        print(f"Call IP: 0x{bc['call_ip']:08x}")
        print(f"Return Address: 0x{bc['return_address']:08x}")
        print(f"Target Sentinel: 0x{state['target']:08x}")
        print(f"ESP at call: 0x{bc['esp']:08x}")
        print(f"Arguments: {[hex(a) for a in bc['arguments']]}")
    print(f"Architectural instructions: {state['instructions']}")
    print(f"Raw instructions: {state['raw_instructions']}")
    print(f"Trace hash (arch): {state['trace_hash']}")
    print(f"Raw trace hash: {state['raw_trace_hash']}")
    print(f"Calls count: {state['calls']}")
    print(f"API calls executed: {len(state['api_calls'])}")
    print(f"Max call depth: {state['maximum_depth']}")
    print(f"Unique observed transfer targets: {len(targets)}")
    print("Registers:")
    for r, v in gprs.items():
        print(f"  {r}: 0x{v:08x}")
    print(f"  eflags: 0x{eflags:08x}")
    print()


if __name__ == "__main__":
    exe = ROOT / "out" / "private" / "SPEED2.EXE"
    
    # Stage -1: Strict toolhelp only, GetLastError not handled
    s_neg1, e_neg1, _ = run_downstream_exploration(exe, stage=-1)
    print_stage_report("Stage -1: Strict Toolhelp Only (stops at GetLastError in _stricmp)", s_neg1, e_neg1)

    # Stage 0: Toolhelp + LastError handled -> QueryPerformanceFrequency
    s0, e0, _ = run_downstream_exploration(exe, stage=0)
    print_stage_report("Stage 0: Downstream Boundary (stops at QueryPerformanceFrequency in 0x43bd90)", s0, e0)

    # Stage 1: QueryPerformanceFrequency handled -> GetCurrentProcess
    s1, e1, _ = run_downstream_exploration(exe, stage=1)
    print_stage_report("Stage 1: Extended (stops at GetCurrentProcess in 0x6f580f)", s1, e1)

    # Stage 2: Process/Thread Handles handled -> timeGetDevCaps
    s2, e2, _ = run_downstream_exploration(exe, stage=2)
    print_stage_report("Stage 2: Further Downstream (stops at timeGetDevCaps in 0x6f5d17)", s2, e2)
