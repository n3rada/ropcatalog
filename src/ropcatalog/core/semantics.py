# Built-in imports
import re
from typing import Any

# Local library imports
from . import registers


CONTROL_MNEMONICS = {
    "call", "int", "int1", "int3", "into", "iret", "iretd", "iretq",
    "jmp", "ret", "retf", "retn", "syscall", "sysenter", "sysret",
}
FLAG_MNEMONICS = {
    "adc", "add", "and", "cmp", "dec", "inc", "neg", "or", "sbb",
    "sub", "test", "xor",
}
READ_ONLY_MNEMONICS = {"cmp", "test"}
READ_WRITE_MNEMONICS = {
    "adc", "add", "and", "dec", "inc", "neg", "not", "or", "rol",
    "ror", "sal", "sar", "sbb", "shl", "shr", "sub", "xor",
}
WRITE_ONLY_MNEMONICS = {
    "bswap", "cmova", "cmovae", "cmovb", "cmovbe", "cmove", "cmovg",
    "cmovge", "cmovl", "cmovle", "cmovne", "lea", "mov", "movsx",
    "movsxd", "movzx",
}
WIDTHS = {"byte": 8, "word": 16, "dword": 32, "qword": 64}


def analyze(instructions: list[str], arch: str) -> dict[str, Any]:
    """Model register, stack, memory, and control effects for a gadget.

    Args:
        instructions: Normalized machine instructions in execution order.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Semantic model containing register, memory, stack, control-flow, and quality effects.
    """
    word_size = 8 if arch == "x64" else 4
    stack_delta = 0
    stack_before_return = 0
    stack_dynamic = False
    return_adjust = 0
    register_reads = set()
    register_writes = set()
    write_details = {}
    assignments = {}
    memory_reads = []
    memory_writes = []
    memory_read_effects = []
    memory_write_effects = []
    stack_pops = []
    stack_slots = []
    controls = []
    control_effects = []
    unknown = []
    assumptions = []
    flags_written = False
    flags_read = False
    pushed_values = []

    for instruction in instructions:
        mnemonic, operands = split_instruction(instruction)
        destination = operands[0] if operands else ""
        sources = operands[1:]

        if mnemonic in CONTROL_MNEMONICS or mnemonic.startswith("j") or mnemonic.startswith("loop"):
            controls.append(instruction)
            control_effects.append(_control_effect(mnemonic, operands, arch))
        if mnemonic in FLAG_MNEMONICS:
            flags_written = True
        if mnemonic in {"adc", "sbb"} or mnemonic.startswith(("cmov", "loop")) or (mnemonic.startswith("j") and mnemonic != "jmp"):
            flags_read = True

        if mnemonic == "pop" and destination:
            offset = stack_before_return
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            for register in _extract_registers(destination, arch):
                stack_pops.append(register)
                if pushed_values:
                    assignments[register] = pushed_values.pop()
                else:
                    stack_slots.append({"kind": "pop", "register": register, "offset": offset})
                    assignments[register] = {"kind": "stack", "offset": offset}
                write_details[register] = _write_detail(destination, arch)
            stack_delta += word_size
            stack_before_return += word_size
        elif mnemonic == "push" and destination:
            _record_read(destination, register_reads, memory_reads, arch)
            memory_writes.append("[stack]")
            pushed_value = _operand_effect(destination, arch)
            pushed_values.append(pushed_value)
            memory_write_effects.append({"address": "[stack]", "value": pushed_value, "width": word_size * 8})
            stack_delta -= word_size
            stack_before_return -= word_size
        elif mnemonic in {"pushad", "pushal"}:
            if arch != "x86":
                unknown.append(instruction)
                continue
            frame_registers = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            register_reads.update(frame_registers)
            memory_writes.append("[stack]")
            memory_write_effects.append({
                "address": "[stack-0x20]",
                "value": {"kind": "register_frame", "registers": frame_registers},
                "width": 256,
            })
            stack_delta -= 32
            stack_before_return -= 32
            stack_dynamic = True
            assumptions.append("pushad return target is register-controlled")
        elif mnemonic in {"popad", "popal"}:
            if arch != "x86":
                unknown.append(instruction)
                continue
            frame = [("edi", 0), ("esi", 4), ("ebp", 8), ("ebx", 16), ("edx", 20), ("ecx", 24), ("eax", 28)]
            for register, offset in frame:
                register_writes.add(register)
                assignments[register] = {"kind": "stack", "offset": stack_before_return + offset}
                stack_pops.append(register)
                stack_slots.append({"kind": "pop", "register": register, "offset": stack_before_return + offset})
                write_details[register] = _write_detail(register, arch)
            stack_slots.append({"kind": "padding", "offset": stack_before_return + 12})
            stack_delta += 32
            stack_before_return += 32
        elif mnemonic in {"ret", "retn", "retf"}:
            return_adjust = _parse_immediate(destination) or 0
            stack_delta += word_size + return_adjust
        elif mnemonic in {"iret", "iretd", "iretq"}:
            frame = 5 * word_size
            stack_delta += frame
            assumptions.append("iret privilege-transition frame")
        elif mnemonic == "leave":
            frame = "rbp" if arch == "x64" else "ebp"
            stack_pointer = "rsp" if arch == "x64" else "esp"
            register_reads.add(frame)
            register_writes.update({frame, stack_pointer})
            assignments[stack_pointer] = {"kind": "register", "value": frame}
            assignments[frame] = {"kind": "memory", "address": f"[{frame}]"}
            stack_dynamic = True
        elif mnemonic == "xchg" and len(operands) == 2:
            left = _operand_effect(operands[0], arch)
            right = _operand_effect(operands[1], arch)
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
                _record_write(operand, register_reads, register_writes, memory_writes, arch)
            if left["kind"] == right["kind"] == "register":
                assignments[left["value"]] = {"kind": "register", "value": right["value"]}
                assignments[right["value"]] = {"kind": "register", "value": left["value"]}
                write_details[left["value"]] = _write_detail(operands[0], arch)
                write_details[right["value"]] = _write_detail(operands[1], arch)
            else:
                memory_operand, other_operand = (operands[0], operands[1]) if "[" in operands[0] else (operands[1], operands[0])
                _record_memory_effects(memory_operand, other_operand, memory_read_effects, memory_write_effects, arch, read_destination=True)
            if _is_stack_pointer(destination, arch) or _is_stack_pointer(sources[0], arch):
                stack_dynamic = True
        elif mnemonic in WRITE_ONLY_MNEMONICS and destination:
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            for operand in sources:
                _record_read(operand, register_reads, memory_reads, arch)
            _assign(mnemonic, destination, sources, assignments, write_details, arch)
            if sources:
                _record_memory_effects(destination, sources[0], memory_read_effects, memory_write_effects, arch)
            if _is_stack_pointer(destination, arch):
                stack_dynamic = True
        elif mnemonic in READ_WRITE_MNEMONICS and destination:
            _record_read(destination, register_reads, memory_reads, arch)
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            for operand in sources:
                _record_read(operand, register_reads, memory_reads, arch)
            _assign(mnemonic, destination, sources, assignments, write_details, arch)
            if sources:
                _record_memory_effects(destination, sources[0], memory_read_effects, memory_write_effects, arch, read_destination=True)
            if _is_stack_pointer(destination, arch):
                immediate = _parse_immediate(sources[0]) if sources else None
                if immediate is None or mnemonic not in {"add", "sub"}:
                    stack_dynamic = True
                else:
                    change = immediate if mnemonic == "add" else -immediate
                    stack_delta += change
                    stack_before_return += change
                    pushed_values.clear()
        elif mnemonic in READ_ONLY_MNEMONICS:
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
        elif mnemonic in CONTROL_MNEMONICS or mnemonic.startswith("j") or mnemonic.startswith("loop"):
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
            if mnemonic == "syscall" and arch == "x64":
                register_writes.update({"rcx", "r11"})
                assignments.update({
                    "rcx": {"kind": "system", "value": "return_address"},
                    "r11": {"kind": "system", "value": "rflags"},
                })
        elif mnemonic not in {"endbr32", "endbr64", "nop", "swapgs"}:
            unknown.append(instruction)

    if any(slot["offset"] < 0 or slot["offset"] >= stack_before_return for slot in stack_slots):
        stack_dynamic = True
        assumptions.append("stack aliasing requires execution validation")
    stack_pointer = "rsp" if arch == "x64" else "esp"
    clobbers = register_writes - {stack_pointer}
    terminator = split_instruction(instructions[-1])[0] if instructions else None
    semantics = {
        "stack_delta": None if stack_dynamic else stack_delta,
        "stack_pops": _ordered_unique(stack_pops),
        "register_reads": sorted(register_reads),
        "register_writes": sorted(register_writes),
        "register_write_details": [
            {"register": register, **write_details[register]}
            for register in sorted(write_details)
        ],
        "assignments": assignments,
        "clobbers": sorted(clobbers),
        "memory_reads": _ordered_unique(memory_reads),
        "memory_writes": _ordered_unique(memory_writes),
        "memory_effects": {
            "reads": _unique_dicts(memory_read_effects),
            "writes": _unique_dicts(memory_write_effects),
        },
        "flags_written": flags_written,
        "flags_read": flags_read,
        "control_flow": controls,
        "control_effects": control_effects,
        "terminator": terminator,
        "unknown": unknown,
        "assumptions": _ordered_unique(assumptions),
        "stack": {
            "dynamic": stack_dynamic,
            "before_return": None if stack_dynamic else stack_before_return,
            "return_adjust": None if stack_dynamic else return_adjust,
            "slots": stack_slots,
        },
    }
    semantics["quality"] = quality_score(semantics, len(instructions))
    return semantics


def quality_score(semantics: dict[str, Any], instruction_count: int) -> dict[str, Any]:
    """Compute a deterministic side-effect cost vector.

    Args:
        semantics: Analyzed gadget side effects.
        instruction_count: Number of instructions in the gadget.

    Returns:
        Total score and its weighted side-effect components.
    """
    components = {
        "instructions": instruction_count,
        "clobbers": len(semantics["clobbers"]) * 4,
        "memory": (len(semantics["memory_reads"]) + len(semantics["memory_writes"])) * 8,
        "control": max(0, len(semantics["control_flow"]) - 1) * 10,
        "flags": 2 if semantics["flags_written"] or semantics["flags_read"] else 0,
        "unknown": len(semantics["unknown"]) * 50,
        "dynamic_stack": 50 if semantics["stack_delta"] is None else 0,
        "non_return": 15 if semantics["terminator"] not in {"ret", "retn"} else 0,
    }
    return {"score": sum(components.values()), "components": components}


def split_instruction(instruction: str) -> tuple[str, list[str]]:
    """Split a normalized instruction into mnemonic and operands.

    Args:
        instruction: Normalized machine instruction to parse or classify.

    Returns:
        Lowercase mnemonic and normalized operands.
    """
    parts = instruction.strip().lower().split(maxsplit=1)
    mnemonic = parts[0] if parts else ""
    operands = [item.strip() for item in parts[1].split(",")] if len(parts) > 1 else []
    return mnemonic, operands


def _extract_registers(operand: str, arch: str) -> list[str]:
    """Extract canonical registers referenced by an operand.

    Args:
        operand: Instruction operand to inspect.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Canonical registers in first-occurrence order.
    """
    found = []
    for token in re.findall(r"\b(?:r1[0-5]|r[8-9]|[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|[abcd][hl]|[sd]il|[sb]pl|r1[0-5][dwbl]|r[8-9][dwbl])\b", operand.lower()):
        if registers.is_register(token, arch):
            found.append(registers.canonical_register(token, arch))
    return _ordered_unique(found)


def _record_read(operand: str, register_reads: set[str], memory_reads: list[str], arch: str) -> None:
    """Record register and memory reads caused by an operand.

    Args:
        operand: Instruction operand to inspect.
        register_reads: Register-read set to update.
        memory_reads: Memory-read expressions to update.
        arch: Target architecture, either ``x86`` or ``x64``.
    """
    register_reads.update(_extract_registers(operand, arch))
    if "[" in operand:
        memory_reads.append(_normalize_memory(operand))


def _record_write(operand: str, register_reads: set[str], register_writes: set[str], memory_writes: list[str], arch: str) -> None:
    """Record register and memory writes caused by an operand.

    Args:
        operand: Instruction operand to inspect.
        register_reads: Register-read set to update.
        register_writes: Register-write set to update.
        memory_writes: Memory-write expressions to update.
        arch: Target architecture, either ``x86`` or ``x64``.
    """
    if "[" in operand:
        register_reads.update(_extract_registers(operand, arch))
        memory_writes.append(_normalize_memory(operand))
    else:
        register_writes.update(_extract_registers(operand, arch))


def _assign(mnemonic: str, destination: str, sources: list[str], assignments: dict[str, Any], write_details: dict[str, Any], arch: str) -> None:
    """Record a symbolic destination assignment when supported.

    Args:
        mnemonic: Normalized instruction mnemonic.
        destination: Destination operand written by the instruction.
        sources: Source operands read by the instruction.
        assignments: Symbolic register assignments to update.
        write_details: Register-width metadata to update.
        arch: Target architecture, either ``x86`` or ``x64``.
    """
    if "[" in destination:
        return
    target_registers = _extract_registers(destination, arch)
    if not target_registers:
        return
    target = target_registers[0]
    detail = _write_detail(destination, arch)
    write_details[target] = detail
    source = _operand_effect(sources[0], arch) if sources else None
    if source and source.get("kind") == "memory" and not source["width"]:
        source["width"] = detail["width"]

    if mnemonic == "xor" and source == {"kind": "register", "value": target}:
        assignment = {"kind": "constant", "value": "0x0"}
    elif mnemonic == "lea" and source and source["kind"] == "memory":
        assignment = {"kind": "address", "value": source["address"]}
    elif mnemonic in {"mov", "movsx", "movsxd", "movzx"} and source:
        assignment = dict(source)
        if mnemonic != "mov":
            assignment["extension"] = mnemonic
    elif mnemonic in READ_WRITE_MNEMONICS or mnemonic == "bswap":
        assignment = {
            "kind": "expression",
            "op": mnemonic,
            "args": [{"kind": "register", "value": target}] + ([source] if source else []),
        }
    elif mnemonic.startswith("cmov") and source:
        assignment = {"kind": "conditional", "value": source, "condition": mnemonic[4:]}
    else:
        assignment = {"kind": "unknown"}

    word_bits = 64 if arch == "x64" else 32
    if detail["width"] < word_bits and not detail["zero_extends"]:
        assignment = {"kind": "partial", "width": detail["width"], "value": assignment}
    assignments[target] = assignment


def _operand_effect(operand: str, arch: str) -> dict[str, Any]:
    """Describe an operand as a register, immediate, or memory effect.

    Args:
        operand: Instruction operand to inspect.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Symbolic register, immediate, memory, or unresolved-symbol effect.
    """
    normalized = operand.strip().lower()
    if "[" in normalized:
        return {"kind": "memory", "address": _normalize_memory(normalized), "width": _operand_width(normalized, arch)}
    found = _extract_registers(normalized, arch)
    if found:
        return {"kind": "register", "value": found[0]}
    immediate = _parse_immediate(normalized)
    if immediate is not None:
        return {"kind": "constant", "value": f"0x{immediate:x}"}
    return {"kind": "symbol", "value": normalized}


def _write_detail(operand: str, arch: str) -> dict[str, Any]:
    """Describe the register width and partial-write behavior.

    Args:
        operand: Instruction operand to inspect.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Destination width and zero-extension or partial-write flags.
    """
    word_bits = 64 if arch == "x64" else 32
    width = _operand_width(operand, arch)
    return {
        "width": width,
        "zero_extends": arch == "x64" and width == 32,
        "partial": width < word_bits and not (arch == "x64" and width == 32),
    }


def _operand_width(operand: str, arch: str) -> int:
    """Return the operand width in bits.

    Args:
        operand: Instruction operand to inspect.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Operand width in bits.
    """
    normalized = operand.lower().strip()
    for prefix, width in WIDTHS.items():
        if re.match(rf"^{prefix}\s", normalized):
            return width
    if "[" in normalized:
        return 0
    registers_found = re.findall(r"\b[a-z0-9]+\b", normalized)
    for register in registers_found:
        if registers.is_register(register, arch):
            if register.startswith("r") and not register[-1:] in {"b", "d", "l", "w"}:
                return 64
            if register.startswith("e") or register.endswith("d"):
                return 32
            if register.endswith("w") or register in {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp"}:
                return 16
            if register.endswith(("b", "l")) or register in {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "spl", "bpl"}:
                return 8
    return 64 if arch == "x64" else 32


def _record_memory_effects(destination: str, source: str, reads: list[dict[str, Any]], writes: list[dict[str, Any]], arch: str, read_destination: bool = False) -> None:
    """Record symbolic memory reads and writes for an instruction.

    Args:
        destination: Destination operand written by the instruction.
        source: Source operand read by the instruction.
        reads: Structured memory reads to update.
        writes: Structured memory writes to update.
        arch: Target architecture, either ``x86`` or ``x64``.
        read_destination: Whether a read-modify-write destination is also recorded as read.
    """
    if "[" in source:
        reads.append({
            "address": _normalize_memory(source),
            "width": _operand_width(source, arch) or _operand_width(destination, arch),
        })
    if "[" in destination:
        effect = {
            "address": _normalize_memory(destination),
            "value": _operand_effect(source, arch),
            "width": _operand_width(destination, arch) or _operand_width(source, arch),
        }
        writes.append(effect)
        if read_destination:
            reads.append({"address": effect["address"], "width": effect["width"]})


def _control_effect(mnemonic: str, operands: list[str], arch: str) -> dict[str, Any]:
    """Describe one explicit control-flow transition.

    Args:
        mnemonic: Normalized instruction mnemonic.
        operands: Instruction operands in source order.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Structured transfer kind, target, and transition metadata.
    """
    effect: dict[str, Any] = {"kind": mnemonic}
    if operands:
        effect["target"] = _operand_effect(operands[0], arch)
    if mnemonic in {"call", "int", "syscall", "sysenter"}:
        effect["effects_after_transfer"] = "unknown"
    if mnemonic in {"iret", "iretd", "iretq"}:
        effect["frame"] = ["ip", "cs", "flags", "sp", "ss"]
    return effect


def _normalize_memory(operand: str) -> str:
    """Normalize a bracketed memory expression.

    Args:
        operand: Instruction operand to inspect.

    Returns:
        Bracketed address expression without memory-width qualifiers.
    """
    return re.sub(r"^(?:byte|word|dword|qword)\s+(?:ptr\s+)?", "", operand).strip()


def _parse_immediate(operand: str) -> int | None:
    """Parse a hexadecimal or decimal immediate value.

    Args:
        operand: Instruction operand to inspect.

    Returns:
        Parsed integer, or ``None`` when the operand is not an immediate.
    """
    value = operand.strip()
    try:
        return int(value, 0)
    except ValueError:
        return None


def _is_stack_pointer(operand: str, arch: str) -> bool:
    """Return whether an operand aliases the architecture stack pointer.

    Args:
        operand: Instruction operand to inspect.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        True when an operand aliases the architecture stack pointer; otherwise ``False``.
    """
    return registers.canonical_register(operand.strip(), arch) == ("rsp" if arch == "x64" else "esp")


def _ordered_unique(values: list[str]) -> list[str]:
    """Remove duplicate strings while preserving encounter order.

    Args:
        values: Strings from which duplicates are removed.

    Returns:
        Strings in first-occurrence order with duplicates removed.
    """
    return list(dict.fromkeys(values))


def _unique_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate dictionaries while preserving encounter order.

    Args:
        values: Dictionaries from which duplicates are removed.

    Returns:
        Dictionaries in first-occurrence order with duplicates removed.
    """
    seen = set()
    results = []
    for value in values:
        key = repr(value)
        if key not in seen:
            seen.add(key)
            results.append(value)
    return results
