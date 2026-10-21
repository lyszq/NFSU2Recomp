#!/usr/bin/env python3
"""Deterministic, explicitly configured RDTSC support for startup probes."""
from __future__ import annotations

from typing import Any


TSC_PROFILE = "deterministic_entry_tsc_v1"
_U32_MASK = 0xFFFFFFFF
_U64_MASK = 0xFFFFFFFFFFFFFFFF


def _valid_counter(value: object) -> bool:
    return type(value) is int and 0 <= value <= _U64_MASK


def apply_rdtsc(engine: Any, registers: Any, address: int, size: int,
                state: dict[str, Any]) -> bool:
    """Emulate RDTSC from an explicit virtual counter in a Unicorn code hook.

    Missing or malformed configuration stops at the instruction without
    changing guest CPU state. A configured counter is split across EDX:EAX,
    and EIP is advanced so Unicorn never executes its host-dependent RDTSC.
    """
    next_value = state.get("virtual_tsc_next")
    increment = state.get("virtual_tsc_increment")
    if (not _valid_counter(next_value) or not _valid_counter(increment)
            or increment == 0):
        target = int(address) & _U32_MASK
        state["status"] = "GUEST_STOP_INSTRUCTION"
        state["target"] = target
        state["instruction_fault"] = {
            "address": target,
            "instruction": "RDTSC",
            "reason": "unconfigured_virtual_tsc",
        }
        engine.emu_stop()
        return False

    value = next_value
    state.setdefault("rdtsc_calls", []).append({
        "address": int(address) & _U32_MASK,
        "value": value,
        "profile": TSC_PROFILE,
    })
    state["virtual_tsc_next"] = (value + increment) & _U64_MASK
    engine.reg_write(registers.UC_X86_REG_EAX, value & _U32_MASK)
    engine.reg_write(registers.UC_X86_REG_EDX, (value >> 32) & _U32_MASK)
    engine.reg_write(registers.UC_X86_REG_EIP,
                     (int(address) + int(size)) & _U32_MASK)
    return True


__all__ = ["TSC_PROFILE", "apply_rdtsc"]
