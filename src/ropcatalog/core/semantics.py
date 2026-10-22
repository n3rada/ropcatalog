import re

from . import registers


CONTROL_MNEMONICS = {
    "call",
    "int",
    "int1",
    "int3",
    "into",
    "iret",
    "iretd",
    "iretq",
    "jmp",
    "ret",
    "retf",
    "retn",
    "syscall",
    "sysenter",
    "sysret",
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


def analyze(instructions: list[str], arch: str) -> dict:
    word_size = 8 if arch == "x64" else 4
    stack_delta = 0
    stack_dynamic = False
    register_reads = set()
    register_writes = set()
    memory_reads = []
    memory_writes = []
    stack_pops = []
    controls = []
    unknown = []
    flags_written = False

    for instruction in instructions:
        mnemonic, operands = _split_instruction(instruction)
        destination = operands[0] if operands else ""
        sources = operands[1:]

        if mnemonic in CONTROL_MNEMONICS or mnemonic.startswith("j") or mnemonic.startswith("loop"):
            controls.append(instruction)
        if mnemonic in FLAG_MNEMONICS:
            flags_written = True

        if mnemonic == "pop" and destination:
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            stack_pops.extend(_extract_registers(destination, arch))
            stack_delta += word_size
        elif mnemonic == "push" and destination:
            _record_read(destination, register_reads, memory_reads, arch)
            memory_writes.append("[stack]")
            stack_delta -= word_size
        elif mnemonic in {"ret", "retn", "retf"}:
            stack_delta += word_size + (_parse_immediate(destination) or 0)
        elif mnemonic == "leave":
            register_reads.add("rbp" if arch == "x64" else "ebp")
            register_writes.update({"rbp", "rsp"} if arch == "x64" else {"ebp", "esp"})
            stack_dynamic = True
        elif mnemonic == "xchg" and len(operands) == 2:
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
                _record_write(operand, register_reads, register_writes, memory_writes, arch)
            if _is_stack_pointer(destination, arch) or _is_stack_pointer(sources[0], arch):
                stack_dynamic = True
        elif mnemonic in WRITE_ONLY_MNEMONICS and destination:
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            for operand in sources:
                _record_read(operand, register_reads, memory_reads, arch)
        elif mnemonic in READ_WRITE_MNEMONICS and destination:
            _record_read(destination, register_reads, memory_reads, arch)
            _record_write(destination, register_reads, register_writes, memory_writes, arch)
            for operand in sources:
                _record_read(operand, register_reads, memory_reads, arch)
            if _is_stack_pointer(destination, arch):
                immediate = _parse_immediate(sources[0]) if sources else None
                if immediate is None or mnemonic not in {"add", "sub"}:
                    stack_dynamic = True
                else:
                    stack_delta += immediate if mnemonic == "add" else -immediate
        elif mnemonic in READ_ONLY_MNEMONICS:
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
        elif mnemonic in CONTROL_MNEMONICS or mnemonic.startswith("j") or mnemonic.startswith("loop"):
            for operand in operands:
                _record_read(operand, register_reads, memory_reads, arch)
        elif mnemonic not in {"endbr32", "endbr64", "nop", "swapgs"}:
            unknown.append(instruction)

    stack_pointer = "rsp" if arch == "x64" else "esp"
    clobbers = register_writes - {stack_pointer}
    terminator = _split_instruction(instructions[-1])[0] if instructions else None
    semantics = {
        "stack_delta": None if stack_dynamic else stack_delta,
        "stack_pops": _ordered_unique(stack_pops),
        "register_reads": sorted(register_reads),
        "register_writes": sorted(register_writes),
        "clobbers": sorted(clobbers),
        "memory_reads": _ordered_unique(memory_reads),
        "memory_writes": _ordered_unique(memory_writes),
        "flags_written": flags_written,
        "control_flow": controls,
        "terminator": terminator,
        "unknown": unknown,
    }
    semantics["quality"] = {
        "score": quality_score(semantics, len(instructions)),
        "instruction_count": len(instructions),
        "side_effect_count": len(semantics["clobbers"]) + len(semantics["memory_reads"]) + len(semantics["memory_writes"]),
    }
    return semantics


def quality_score(semantics: dict, instruction_count: int) -> int:
    stack_delta = semantics["stack_delta"]
    extra_controls = max(len(semantics["control_flow"]) - 1, 0)
    stack_penalty = 50 if stack_delta is None else abs(stack_delta)
    terminator_penalty = 0 if semantics["terminator"] in {"ret", "retn", "retf"} else 50
    return (
        instruction_count * 10
        + len(semantics["clobbers"]) * 6
        + len(semantics["memory_reads"]) * 8
        + len(semantics["memory_writes"]) * 20
        + extra_controls * 30
        + len(semantics["unknown"]) * 15
        + stack_penalty
        + terminator_penalty
    )


def _split_instruction(instruction: str) -> tuple[str, list[str]]:
    parts = instruction.strip().lower().split(maxsplit=1)
    if not parts:
        return "", []
    operands = [operand.strip() for operand in parts[1].split(",")] if len(parts) > 1 else []
    return parts[0], operands


def _extract_registers(operand: str, arch: str) -> list[str]:
    found = []
    available = registers.get_registers(arch)
    for candidate in re.findall(r"\b(?:r1[0-5]|r[89]|[er]?(?:ax|bx|cx|dx|si|di|sp|bp)|[abcd][hl]|[sd]il|[sb]pl)(?:d|w|b)?\b", operand):
        if candidate in available:
            found.append(registers.canonical_register(candidate, arch))
    return _ordered_unique(found)


def _record_read(operand: str, register_reads: set[str], memory_reads: list[str], arch: str) -> None:
    register_reads.update(_extract_registers(operand, arch))
    if "[" in operand:
        memory_reads.append(_normalize_memory(operand))


def _record_write(
    operand: str,
    register_reads: set[str],
    register_writes: set[str],
    memory_writes: list[str],
    arch: str,
) -> None:
    if "[" in operand:
        register_reads.update(_extract_registers(operand, arch))
        memory_writes.append(_normalize_memory(operand))
    else:
        register_writes.update(_extract_registers(operand, arch))


def _normalize_memory(operand: str) -> str:
    return re.sub(r"^(?:byte|word|dword|qword)\s+(?:ptr\s+)?", "", operand).strip()


def _parse_immediate(operand: str) -> int | None:
    value = operand.strip()
    try:
        return int(value, 0)
    except ValueError:
        return None


def _is_stack_pointer(operand: str, arch: str) -> bool:
    return registers.canonical_register(operand.strip(), arch) == ("rsp" if arch == "x64" else "esp")


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
