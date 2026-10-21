#!/usr/bin/env python3
"""Narrow CPUID profile used by the synthetic guest startup oracle."""
from __future__ import annotations

from typing import Any


_CPUID_VALUES: dict[int, tuple[int, int, int, int]] = {
    # Existing runtime/dispatch.c cpuid_shim profile: GenuineIntel family/model
    # leaf and the advertised maximum basic leaf.
    0x00000000: (0x00000001, 0x756E6547, 0x6C65746E, 0x49656E69),
    0x00000001: (0x000006D8, 0x00000000, 0x00000000, 0x0383FBFF),
    # The static upstream profile advertises no extended feature bits. The
    # observed query is modeled explicitly as zero rather than delegated to
    # Unicorn's host-dependent CPUID implementation.
    0x80000000: (0, 0, 0, 0),
    0x80000001: (0, 0, 0, 0),
}


def cpuid_values(leaf: int) -> tuple[int, int, int, int] | None:
    """Return EAX, EBX, ECX, EDX for a supported leaf, else ``None``."""
    return _CPUID_VALUES.get(int(leaf) & 0xFFFFFFFF)


def apply_cpuid(engine: Any, registers: Any, address: int, size: int,
                state: dict[str, Any]) -> bool:
    """Emulate a supported CPUID leaf from a Unicorn code hook.

    Returning ``True`` means the instruction was handled. Unknown leaves stop
    execution at the CPUID instruction and return ``False`` without changing
    guest registers.
    """
    leaf = int(engine.reg_read(registers.UC_X86_REG_EAX)) & 0xFFFFFFFF
    values = cpuid_values(leaf)
    if values is None:
        target = int(address) & 0xFFFFFFFF
        state["status"] = "GUEST_STOP_INSTRUCTION"
        state["target"] = target
        state["instruction_fault"] = {
            "address": target,
            "instruction": "CPUID",
            "leaf": leaf,
            "reason": "unsupported_cpuid_leaf",
        }
        engine.emu_stop()
        return False

    eax, ebx, ecx, edx = values
    state.setdefault("cpuid_calls", []).append({
        "address": int(address) & 0xFFFFFFFF, "leaf": leaf,
        "eax": eax, "ebx": ebx, "ecx": ecx, "edx": edx,
    })
    engine.reg_write(registers.UC_X86_REG_EAX, eax)
    engine.reg_write(registers.UC_X86_REG_EBX, ebx)
    engine.reg_write(registers.UC_X86_REG_ECX, ecx)
    engine.reg_write(registers.UC_X86_REG_EDX, edx)
    engine.reg_write(registers.UC_X86_REG_EIP,
                      (int(address) + int(size)) & 0xFFFFFFFF)
    return True


__all__ = ["apply_cpuid", "cpuid_values"]
