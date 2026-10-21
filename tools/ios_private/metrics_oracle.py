"""Independent bounded USER32 metric: declared primary-button guest policy."""
import struct

from window_oracle import _range_has_permissions, _memory_fault


def apply_metrics(engine, registers, unicorn_module, row, mapped_ranges, state):
    if row.get("library", "").casefold() != "user32.dll" or row.get("name") != "GetSystemMetrics":
        return False
    esp = int(engine.reg_read(registers.UC_X86_REG_ESP)) & 0xffffffff
    if not _range_has_permissions(engine, esp, 8, unicorn_module.UC_PROT_READ, mapped_ranges):
        _memory_fault(state, "read", esp, 8)
        return False
    ret, index = struct.unpack("<II", engine.mem_read(esp, 8))
    if index != 23:  # SM_SWAPBUTTON; screen metrics are not modeled.
        return False
    state["api_calls"].append({
        "library": row["library"], "name": row["name"],
        "import_index": row["index"], "tag": 0xf0000000 + row["index"],
        "call_ip": state["last_ip"], "esp_before": esp, "argument_count": 1,
        "return_address": ret, "arguments": [index], "result": 0,
        "profile": "primary_button_left", "esp_after": (esp + 8) & 0xffffffff,
    })
    engine.reg_write(registers.UC_X86_REG_EAX, 0)
    engine.reg_write(registers.UC_X86_REG_EIP, ret)
    engine.reg_write(registers.UC_X86_REG_ESP, (esp + 8) & 0xffffffff)
    state["resume"] = True
    return True
