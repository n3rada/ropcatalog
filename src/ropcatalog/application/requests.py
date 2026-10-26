"""Validated batch and JSONL request models."""

# Built-in imports
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any

# Local library imports
from ..core import registers
from ..core import synthesis

@dataclass(frozen=True)
class Query:
    identifier: str
    command: str
    raw_gadget: bool = False
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlanStep:
    command: str
    raw_gadget: bool = False
    constraints: dict[str, Any] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Plan:
    identifier: str
    steps: tuple[PlanStep, ...]
    alignment: dict[str, int] | None = None


@dataclass(frozen=True)
class Synthesis:
    identifier: str
    specification: dict[str, Any]


@dataclass(frozen=True)
class GadgetLookup:
    identifier: str
    gadget_id: str


BatchRequest = Query | Plan | Synthesis | GadgetLookup


def parse_batch_queries(path: str) -> list[BatchRequest]:
    """Read and validate plain or JSONL batch requests.

    Args:
        path: Batch request path, or ``-`` for standard input.

    Returns:
        Validated requests in input order.

    Raises:
        ValueError: If the path cannot be read or any request is invalid.
    """
    if path == "-":
        lines = sys.stdin
    else:
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise ValueError(f"cannot read batch file '{path}': {error}") from error

    queries = []
    for line_number, line in enumerate(lines, 1):
        query = _parse_batch_line(line, line_number)
        if query is not None:
            queries.append(query)
    return queries


def _parse_batch_line(line: str, line_number: int) -> BatchRequest | None:
    """Parse one batch input line into a typed request.

    Args:
        line: One batch-input line.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Typed request, or ``None`` for blank and comment lines.

    Raises:
        ValueError: If the line is not a supported plain or JSON request.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith("{"):
        return Query(str(line_number), line, True)
    try:
        request = json.loads(line)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON on batch line {line_number}: {error.msg}") from error
    if not isinstance(request, dict):
        raise ValueError(f"batch line {line_number} must be a JSON object")
    has_query = "query" in request
    has_command = "command" in request
    has_plan = "plan" in request
    has_synthesis = "synthesize" in request
    has_lookup = "gadget_id" in request
    if sum((has_query, has_command, has_plan, has_synthesis, has_lookup)) != 1:
        raise ValueError(
            f"batch line {line_number} requires exactly one of 'query', 'command', 'plan', 'synthesize', or 'gadget_id'"
        )
    if has_synthesis:
        if set(request) - {"id", "synthesize"}:
            raise ValueError(f"batch line {line_number} synthesis accepts only 'id' and 'synthesize'")
        return _parse_synthesis(request, line_number)
    if has_lookup:
        if set(request) - {"id", "gadget_id"}:
            raise ValueError(f"batch line {line_number} gadget lookup accepts only 'id' and 'gadget_id'")
        if not isinstance(request["gadget_id"], str) or not re.fullmatch(r"[0-9a-fA-F]{16}", request["gadget_id"]):
            raise ValueError(f"batch line {line_number} gadget_id must be a 16-character hexadecimal ID")
        return GadgetLookup(str(request.get("id", line_number)), request["gadget_id"].lower())
    if has_plan:
        unexpected = sorted(set(request) - {"alignment", "id", "plan"})
        if unexpected:
            raise ValueError(f"batch line {line_number} has unsupported plan keys: {', '.join(unexpected)}")
        return _parse_plan(request, line_number)
    unexpected = sorted(set(request) - {"id", "query", "command", "constraints"})
    if unexpected:
        raise ValueError(f"batch line {line_number} has unsupported query keys: {', '.join(unexpected)}")
    command = request["query"] if has_query else request["command"]
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"batch line {line_number} requires a non-empty query or command")
    return Query(
        str(request.get("id", line_number)),
        command.strip(),
        has_query,
        _parse_constraints(request.get("constraints"), line_number),
    )


def _parse_plan(request: dict[str, Any], line_number: int) -> Plan:
    """Validate and normalize a fixed-plan request.

    Args:
        request: Decoded JSON request object.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated fixed-plan request.

    Raises:
        ValueError: If the plan or one of its steps violates the request schema.
    """
    steps = request["plan"]
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"batch line {line_number} plan requires a non-empty step list")
    parsed_steps = []
    for step_number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ValueError(f"batch line {line_number} plan step {step_number} must be an object")
        unexpected = sorted(set(step) - {"query", "command", "constraints", "values"})
        if unexpected:
            raise ValueError(f"batch line {line_number} plan step {step_number} has unsupported keys: {', '.join(unexpected)}")
        has_query = "query" in step
        has_command = "command" in step
        if has_query == has_command:
            raise ValueError(f"batch line {line_number} plan step {step_number} requires exactly one of 'query' or 'command'")
        command = step["query"] if has_query else step["command"]
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"batch line {line_number} plan step {step_number} requires a non-empty query or command")
        values = step.get("values", {})
        if not isinstance(values, dict) or not all(isinstance(key, str) and key.strip() for key in values):
            raise ValueError(f"batch line {line_number} plan step {step_number} values must be an object keyed by register")
        parsed_steps.append(PlanStep(
            command=command.strip(),
            raw_gadget=has_query,
            constraints=_parse_constraints(step.get("constraints"), line_number),
            values={key.lower().strip(): value for key, value in values.items()},
        ))
    alignment = request.get("alignment")
    if alignment is not None:
        if not isinstance(alignment, dict) or set(alignment) != {"modulus", "initial", "final"}:
            raise ValueError(f"batch line {line_number} alignment requires modulus, initial, and final")
        modulus = alignment["modulus"]
        initial = alignment["initial"]
        final = alignment["final"]
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (modulus, initial, final)):
            raise ValueError(f"batch line {line_number} alignment values must be integers")
        if modulus < 1 or not 0 <= initial < modulus or not 0 <= final < modulus:
            raise ValueError(f"batch line {line_number} alignment residues must be within the modulus")
    return Plan(str(request.get("id", line_number)), tuple(parsed_steps), alignment)


def _parse_synthesis(request: dict[str, Any], line_number: int) -> Synthesis:
    """Validate and normalize a bounded synthesis request.

    Args:
        request: Decoded JSON request object.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated chain synthesis request.

    Raises:
        ValueError: If the synthesis specification violates its schema.
    """
    value = request["synthesize"]
    if not isinstance(value, dict):
        raise ValueError(f"batch line {line_number} synthesize must be an object")
    allowed = {
        "bad_bytes", "bases", "call", "constraints", "emit", "filler", "locked", "max_words",
        "mitigations", "postconditions", "profile", "scratch", "search", "set",
        "transition", "verify", "write",
    }
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise ValueError(f"batch line {line_number} synthesis has unsupported keys: {', '.join(unexpected)}")

    profile = value.get("profile", "none")
    if profile not in synthesis.ABI_ARGUMENTS:
        raise ValueError(f"batch line {line_number} synthesis has unsupported profile '{profile}'")
    constraints = _parse_constraints(value.get("constraints"), line_number)
    profile_arch = "x64" if "x64" in profile else ("x86" if profile == "x86-cdecl" else None)
    if profile_arch and constraints.get("arch") and constraints["arch"] != [profile_arch]:
        raise ValueError(f"batch line {line_number} synthesis profile conflicts with architecture constraint")
    if profile_arch:
        constraints["arch"] = [profile_arch]
    constraints["forbid"] = sorted(set(constraints.get("forbid", [])) | {"unknown"})

    postconditions = value.get("postconditions", {})
    if not isinstance(postconditions, dict) or set(postconditions) - {"set", "write"}:
        raise ValueError(f"batch line {line_number} postconditions accepts only set and write")
    set_values = _parse_set(value.get("set", {}), line_number)
    for register, target in _parse_set(postconditions.get("set", {}), line_number).items():
        if register in set_values and set_values[register] != target:
            raise ValueError(f"batch line {line_number} has conflicting set value for {register}")
        set_values[register] = target
    writes = _parse_writes(value.get("write", []), line_number)
    writes.extend(_parse_writes(postconditions.get("write", []), line_number))
    transition = _parse_transition(value.get("transition"), line_number)
    call = _parse_call(value.get("call"), line_number)
    if transition and call:
        raise ValueError(f"batch line {line_number} synthesis cannot combine transition and direct call")
    if not set_values and not writes and not transition and not call:
        raise ValueError(f"batch line {line_number} synthesis requires at least one goal")

    bases = value.get("bases", {})
    if not isinstance(bases, dict) or not all(
        isinstance(module, str) and module and isinstance(base, (str, int)) and not isinstance(base, bool)
        for module, base in bases.items()
    ):
        raise ValueError(f"batch line {line_number} bases must map module names to strings or integers")
    mitigations = value.get("mitigations", [])
    if isinstance(mitigations, str):
        mitigations = [mitigations]
    if not isinstance(mitigations, list) or set(mitigations) - {"cet", "cfg", "kpti", "smap", "smep"}:
        raise ValueError(f"batch line {line_number} mitigations must contain cet, cfg, kpti, smap, or smep")
    emit = value.get("emit", [])
    if isinstance(emit, str):
        emit = [emit]
    if not isinstance(emit, list) or set(emit) - {"python", "pwntools"}:
        raise ValueError(f"batch line {line_number} emit must contain python or pwntools")
    verify = value.get("verify", "syntactic")
    if verify not in {"bytes", "emulate", "syntactic"}:
        raise ValueError(f"batch line {line_number} verify must be bytes, emulate, or syntactic")
    search = _parse_search(value.get("search"), line_number)
    max_words = value.get("max_words", 256)
    if not isinstance(max_words, int) or isinstance(max_words, bool) or max_words < 1:
        raise ValueError(f"batch line {line_number} max_words must be a positive integer")
    specification = {
        "abi": profile,
        "bad_bytes": _parse_bad_bytes(value.get("bad_bytes", []), line_number),
        "bases": bases,
        "call": call,
        "constraints": constraints,
        "emit": emit,
        "filler": value.get("filler", "<filler>"),
        "locked": _parse_locked(value.get("locked", []), line_number),
        "max_words": max_words,
        "mitigations": sorted(set(mitigations)),
        "scratch": _parse_scratch(value.get("scratch", []), line_number),
        "search": search,
        "set": set_values,
        "transition": transition,
        "verify": verify,
        "write": writes,
    }
    return Synthesis(str(request.get("id", line_number)), specification)


def _parse_set(value: Any, line_number: int) -> dict[str, str | int]:
    """Parse desired register values from a synthesis request.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Canonical desired register values.

    Raises:
        ValueError: If register assignments are malformed.
    """
    if not isinstance(value, dict):
        raise ValueError(f"batch line {line_number} set must be an object keyed by general register")
    if not all(
        isinstance(register, str)
        and (registers.is_register(register, "x64") or registers.is_register(register, "x86"))
        and isinstance(target, (str, int)) and not isinstance(target, bool)
        for register, target in value.items()
    ):
        raise ValueError(f"batch line {line_number} set must map general registers to strings or integers")
    return {register.lower().strip(): target for register, target in value.items()}


def _parse_writes(value: Any, line_number: int) -> list[dict[str, Any]]:
    """Parse arbitrary-memory-write synthesis goals.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated arbitrary-memory-write goals.

    Raises:
        ValueError: If memory-write goals are malformed.
    """
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError(f"batch line {line_number} write must be an object or list")
    results = []
    for goal in value:
        if not isinstance(goal, dict) or not {"address", "value"}.issubset(goal) or set(goal) - {"address", "value", "width"}:
            raise ValueError(f"batch line {line_number} write requires address, value, and optional width")
        if not isinstance(goal["address"], str) or not goal["address"].strip():
            raise ValueError(f"batch line {line_number} write address must be a string")
        expected = goal["value"]
        if isinstance(expected, dict):
            if set(expected) != {"register"} or not isinstance(expected["register"], str):
                raise ValueError(f"batch line {line_number} write register value is invalid")
        elif not isinstance(expected, (str, int)) or isinstance(expected, bool):
            raise ValueError(f"batch line {line_number} write value must be a register object, string, or integer")
        width = goal.get("width")
        if width not in {None, 8, 16, 32, 64}:
            raise ValueError(f"batch line {line_number} write width must be 8, 16, 32, or 64")
        results.append(dict(goal, address=goal["address"].lower().strip()))
    return results


def _parse_transition(value: Any, line_number: int) -> dict[str, Any] | None:
    """Parse an optional indirect or privilege-transition goal.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated transition goal, or ``None`` when absent.

    Raises:
        ValueError: If the transition goal is malformed.
    """
    if value is None:
        return None
    if not isinstance(value, dict) or "kind" not in value or set(value) - {"frame", "kind", "target"}:
        raise ValueError(f"batch line {line_number} transition requires kind and optional target")
    if value["kind"] not in synthesis.SUPPORTED_CONTROLS:
        raise ValueError(f"batch line {line_number} transition kind is unsupported")
    target = value.get("target")
    if target is not None and (
        not isinstance(target, dict) or set(target) != {"register"}
        or not isinstance(target["register"], str)
    ):
        raise ValueError(f"batch line {line_number} transition target must be a register object")
    frame = value.get("frame")
    if frame is not None:
        expected = {"ip", "cs", "flags", "sp", "ss"}
        if value["kind"] not in {"iret", "iretd", "iretq"} or not isinstance(frame, dict) or set(frame) != expected:
            raise ValueError(f"batch line {line_number} iret frame requires ip, cs, flags, sp, and ss")
        if not all(isinstance(item, (str, int)) and not isinstance(item, bool) for item in frame.values()):
            raise ValueError(f"batch line {line_number} iret frame values must be strings or integers")
    return value


def _parse_call(value: Any, line_number: int) -> dict[str, Any] | None:
    """Parse an optional direct ABI call goal.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated ABI call goal, or ``None`` when absent.

    Raises:
        ValueError: If the ABI call goal is malformed.
    """
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"address", "address_kind", "arguments", "module", "return", "symbol"}:
        raise ValueError(f"batch line {line_number} direct call is invalid")
    if ("address" in value) == ("symbol" in value):
        raise ValueError(f"batch line {line_number} direct call requires exactly one of address or symbol")
    result = dict(value)
    if "address" in value:
        if not isinstance(value["address"], str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value["address"]):
            raise ValueError(f"batch line {line_number} direct call address must be hexadecimal")
        if value.get("address_kind", "rva") not in {"rva", "va"}:
            raise ValueError(f"batch line {line_number} direct call address_kind must be rva or va")
        result["address_kind"] = value.get("address_kind", "rva")
    elif not isinstance(value["symbol"], str) or not value["symbol"].strip():
        raise ValueError(f"batch line {line_number} direct call symbol must be non-empty")
    arguments = value.get("arguments", [])
    if not isinstance(arguments, list) or not all(isinstance(argument, (str, int)) and not isinstance(argument, bool) for argument in arguments):
        raise ValueError(f"batch line {line_number} direct call arguments must be a list of strings or integers")
    result["arguments"] = arguments
    return result


def _parse_search(value: Any, line_number: int) -> dict[str, int]:
    """Parse bounded beam-search limits.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Validated search bounds with defaults applied.

    Raises:
        ValueError: If search bounds are malformed.
    """
    defaults = {"beam_width": 32, "max_depth": 8, "max_nodes": 5000, "per_effect": 16}
    if value is None:
        return defaults
    if not isinstance(value, dict) or set(value) - set(defaults):
        raise ValueError(f"batch line {line_number} search accepts beam_width, max_depth, max_nodes, and per_effect")
    for key, item in value.items():
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise ValueError(f"batch line {line_number} search value '{key}' must be a positive integer")
        defaults[key] = item
    return defaults


def _parse_bad_bytes(value: Any, line_number: int) -> list[str]:
    """Parse hexadecimal bytes forbidden in resolved chain words.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Normalized forbidden byte strings.

    Raises:
        ValueError: If the forbidden-byte list is malformed.
    """
    if isinstance(value, str):
        value = re.findall(r"(?:\\x)?([0-9a-fA-F]{2})", value)
    if not isinstance(value, list) or not all(isinstance(byte, str) and re.fullmatch(r"[0-9a-fA-F]{2}", byte) for byte in value):
        raise ValueError(f"batch line {line_number} bad_bytes must be byte hex strings")
    return sorted(set(byte.lower() for byte in value))


def _parse_scratch(value: Any, line_number: int) -> list[str]:
    """Parse candidate writable scratch addresses.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Normalized scratch address strings.

    Raises:
        ValueError: If a scratch address is malformed.
    """
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, (str, int)) and not isinstance(item, bool) and str(item).strip() for item in value):
        raise ValueError(f"batch line {line_number} scratch must contain strings or integers")
    return value


def _parse_locked(value: Any, line_number: int) -> list[str]:
    """Parse stable gadget IDs forced into the synthesized prefix.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Normalized locked gadget IDs.

    Raises:
        ValueError: If a locked gadget ID is malformed.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{16}", item) for item in value):
        raise ValueError(f"batch line {line_number} locked must be a list of gadget IDs")
    return [item.lower() for item in value]


def _parse_constraints(value: Any, line_number: int) -> dict[str, Any]:
    """Validate semantic filtering and ranking constraints.

    Args:
        value: Input value to parse, validate, or normalize.
        line_number: One-based batch line number used in validation errors.

    Returns:
        Normalized filtering and ranking constraints.

    Raises:
        ValueError: If a constraint is unknown or malformed.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"batch line {line_number} constraints must be a JSON object")

    allowed = {
        "arch", "forbid", "max_stack_delta", "modules", "preserve",
        "require_reads", "require_writes", "terminator",
    }
    unsupported = sorted(set(value) - allowed)
    if unsupported:
        raise ValueError(
            f"batch line {line_number} has unsupported constraints: {', '.join(unsupported)}"
        )

    constraints = {}
    for key in ("arch", "forbid", "modules", "preserve", "require_reads", "require_writes", "terminator"):
        if key not in value:
            continue
        items = value[key]
        if isinstance(items, str):
            items = [items]
        if not isinstance(items, list) or not items or not all(isinstance(item, str) and item.strip() for item in items):
            raise ValueError(f"batch line {line_number} constraint '{key}' requires a string or non-empty string list")
        constraints[key] = [item.lower().strip() for item in items]

    unsupported_forbid = sorted(
        set(constraints.get("forbid", []))
        - {"call", "flags", "jump", "memory_read", "memory_write", "syscall", "unknown"}
    )
    if unsupported_forbid:
        raise ValueError(f"batch line {line_number} has unsupported forbid values: {', '.join(unsupported_forbid)}")
    unsupported_arch = sorted(set(constraints.get("arch", [])) - {"x86", "x64"})
    if unsupported_arch:
        raise ValueError(f"batch line {line_number} has unsupported architectures: {', '.join(unsupported_arch)}")

    if "max_stack_delta" in value:
        maximum = value["max_stack_delta"]
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
            raise ValueError(f"batch line {line_number} constraint 'max_stack_delta' requires a non-negative integer")
        constraints["max_stack_delta"] = maximum
    return constraints


