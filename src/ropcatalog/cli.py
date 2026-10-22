# Built-in imports
import argparse
from collections import Counter
from dataclasses import dataclass, field
import io
import json
import re
import sys
from pathlib import Path

# Local library imports
from .core import gadgets
from .core import registers
from .core import utils
from .core import formatters
from .core import terminal
from .core import synthesis
from .core import verification


@dataclass(frozen=True)
class Query:
    identifier: str
    command: str
    raw_gadget: bool = False
    constraints: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PlanStep:
    command: str
    raw_gadget: bool = False
    constraints: dict = field(default_factory=dict)
    values: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Plan:
    identifier: str
    steps: tuple[PlanStep, ...]
    alignment: dict | None = None


@dataclass(frozen=True)
class Synthesis:
    identifier: str
    specification: dict


@dataclass(frozen=True)
class GadgetLookup:
    identifier: str
    gadget_id: str


class RopCatalogArgumentParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)
        noninteractive = (
            parsed.command is not None
            or bool(parsed.query)
            or parsed.batch is not None
            or parsed.serve
        )
        if parsed.capabilities:
            if (
                parsed.paths or noninteractive or parsed.jsonl or parsed.limit is not None
                or parsed.artifact_dir or parsed.catalog_out or parsed.fields
                or parsed.bad_characters or parsed.all or parsed.offset
                or parsed.encoding or parsed.style != "plain" or parsed.verbose
                or parsed.stdin_module or parsed.address_kind != "unknown"
            ):
                self.error("--capabilities must be used alone")
            return parsed
        job_requested = noninteractive or parsed.catalog_out is not None
        if not parsed.paths:
            if args is None and job_requested and not parsed.serve and not sys.stdin.isatty():
                parsed.paths = ["-"]
            else:
                self.error("provide an input path or pipe gadget output on standard input")
        if parsed.jsonl and not noninteractive:
            self.error("--jsonl requires --command, --query, --batch, or --serve")
        if parsed.artifact_dir and not parsed.jsonl:
            self.error("--artifact-dir requires --jsonl")
        if parsed.serve and parsed.artifact_dir:
            self.error("--serve cannot be combined with --artifact-dir")
        if parsed.artifact_dir and parsed.verbose:
            self.error("--verbose cannot be combined with --artifact-dir")
        if parsed.fields and not (parsed.jsonl or parsed.serve):
            self.error("--fields requires --jsonl or --serve")
        if parsed.catalog_out and (
            noninteractive or parsed.jsonl or parsed.artifact_dir or parsed.limit is not None
            or parsed.fields or parsed.all or parsed.offset or parsed.style != "plain"
            or parsed.verbose
        ):
            self.error("--catalog-out cannot be combined with query or JSONL output options")
        if parsed.limit is not None and not noninteractive:
            self.error("--limit requires --command, --query, --batch, or --serve")
        if parsed.paths.count("-") > 1:
            self.error("standard input may only be specified once")
        if "-" in parsed.paths and not job_requested:
            self.error("standard input requires a non-interactive query or --catalog-out")
        if "-" in parsed.paths and parsed.batch == "-":
            self.error("standard input cannot provide both gadgets and batch queries")
        if "-" in parsed.paths and parsed.serve:
            self.error("standard input cannot provide both gadgets and served requests")
        if parsed.stdin_module and "-" not in parsed.paths:
            self.error("--stdin-module requires a standard-input gadget source")
        if parsed.offset and parsed.address_kind == "va":
            self.error("--offset cannot rebase addresses marked as virtual addresses")
        if parsed.artifact_dir and parsed.fields and "module" not in parsed.fields:
            self.error("--artifact-dir requires the 'module' JSONL field")
        return parsed


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def output_fields(value: str) -> tuple[str, ...]:
    available = {
        "address", "address_kind", "arch", "bytes", "cost", "extractor", "extractor_version",
        "formatted", "id", "instructions", "module", "raw", "semantics", "source_id",
        "source_sha256",
    }
    fields = tuple(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))
    unsupported = sorted(set(fields) - available)
    if not fields:
        raise argparse.ArgumentTypeError("must contain at least one output field")
    if unsupported:
        raise argparse.ArgumentTypeError(f"unsupported fields: {', '.join(unsupported)}")
    return fields


def non_empty_string(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = RopCatalogArgumentParser(
        prog="ropcatalog",
        add_help=True,
        description="Fast x86/x64 gadget retrieval from rp++, ROPgadget, and Ropper output.",
        exit_on_error=True,
    )

    parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to rp++, ROPgadget, Ropper, or reusable catalog files/directories; use '-' for standard input.",
    )

    parser.add_argument(
        "-b",
        "--bad-characters",
        type=str,
        default="",
        required=False,
        help=r"A string of characters to exclude in the format '\x00\x0a\x0d'.",
    )

    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Disable default uniqueness filtering (show all duplicate gadgets).",
    )

    parser.add_argument(
        "-s",
        "--style",
        choices=["plain", "python", "js", "cpp"],
        default="plain",
        help="Output format style (default: plain).",
    )


    parser.add_argument(
        "-o",
        "--offset",
        action="store_true",
        help="Prefix addresses with base address variable (for ASLR rebasing).",
    )

    parser.add_argument(
        "-e",
        "--encoding",
        type=str,
        default=None,
        required=False,
        help="File encoding (e.g., utf-8, utf-16). Auto-detected if not set.",
    )
    parser.add_argument(
        "--address-kind",
        choices=["unknown", "rva", "va"],
        default="unknown",
        help="Describe extractor addresses as unknown, relative, or virtual addresses.",
    )

    query_source = parser.add_mutually_exclusive_group()
    query_source.add_argument(
        "-c",
        "--command",
        type=non_empty_string,
        default=None,
        required=False,
        help="Run a single command and exit (e.g., -c 'pivot reg'). Useful for piping output.",
    )
    query_source.add_argument(
        "-q",
        "--query",
        action="append",
        type=non_empty_string,
        default=[],
        help="Run an exact gadget query and exit. Repeat to execute multiple queries.",
    )
    query_source.add_argument(
        "--batch",
        type=non_empty_string,
        default=None,
        metavar="PATH",
        help="Read newline-delimited queries from PATH, or '-' for standard input. Use instead of --command or --query.",
    )
    query_source.add_argument(
        "--serve",
        action="store_true",
        help="Keep the catalog loaded and answer JSONL requests on standard input.",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Emit one JSON object per query to stdout, suitable for jq pipelines or agents.",
    )
    parser.add_argument(
        "--limit",
        type=positive_integer,
        default=None,
        help="Return at most this many gadgets per query. Requires a non-interactive query mode.",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help="Write JSONL to <module>.ropcatalog.jsonl files instead of stdout.",
    )
    parser.add_argument(
        "--catalog-out",
        type=Path,
        default=None,
        help="Write a reusable gadget catalog and exit.",
    )
    parser.add_argument(
        "--stdin-module",
        type=non_empty_string,
        default=None,
        metavar="NAME",
        help="Name a gadget source read from standard input.",
    )
    parser.add_argument(
        "--fields",
        type=output_fields,
        default=None,
        metavar="FIELD,...",
        help="Select gadget fields in JSONL output to reduce output size.",
    )
    parser.add_argument(
        "--capabilities",
        action="store_true",
        help="Print the machine-readable interface contract and exit.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Keep routine diagnostics when producing machine-readable output.",
    )
    return parser


def parse_batch_queries(path: str) -> list[Query]:
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


def _parse_batch_line(line: str, line_number: int):
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


def _parse_plan(request: dict, line_number: int) -> Plan:
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


def _parse_synthesis(request: dict, line_number: int) -> Synthesis:
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


def _parse_set(value, line_number):
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


def _parse_writes(value, line_number):
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


def _parse_transition(value, line_number):
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


def _parse_call(value, line_number):
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


def _parse_search(value, line_number):
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


def _parse_bad_bytes(value, line_number):
    if isinstance(value, str):
        value = re.findall(r"(?:\\x)?([0-9a-fA-F]{2})", value)
    if not isinstance(value, list) or not all(isinstance(byte, str) and re.fullmatch(r"[0-9a-fA-F]{2}", byte) for byte in value):
        raise ValueError(f"batch line {line_number} bad_bytes must be byte hex strings")
    return sorted(set(byte.lower() for byte in value))


def _parse_scratch(value, line_number):
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, (str, int)) and not isinstance(item, bool) and str(item).strip() for item in value):
        raise ValueError(f"batch line {line_number} scratch must contain strings or integers")
    return value


def _parse_locked(value, line_number):
    if not isinstance(value, list) or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{16}", item) for item in value):
        raise ValueError(f"batch line {line_number} locked must be a list of gadget IDs")
    return [item.lower() for item in value]


def gadget_to_record(gadget, formatter, with_base_address: bool, fields=None, cost=None) -> dict:
    record = {
        "id": gadget.identifier,
        "source_id": gadget.source_id,
        "source_sha256": gadget.source_sha256,
        "extractor": gadget.extractor,
        "extractor_version": gadget.extractor_version,
        "module": gadget.module,
        "address": gadget.address,
        "address_kind": gadget.address_kind,
        "arch": gadget.arch,
        "bytes": gadget.bytes_hex,
        "instructions": gadget.instructions,
        "semantics": gadget.semantics,
        "raw": gadget.raw,
        "formatted": formatter.format(gadget, with_base_address),
        "cost": cost,
    }
    if gadget.bytes_hex is None:
        record.pop("bytes")
    if gadget.extractor_version is None:
        record.pop("extractor_version")
    if cost is None:
        record.pop("cost")
    if fields:
        return {field: record.get(field) for field in fields}
    return record


def _parse_constraints(value, line_number: int) -> dict:
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


def _apply_constraints(candidates: list, constraints: dict) -> tuple[list, dict, dict]:
    accepted = []
    rejection_counts = Counter()
    rejected_by = {}
    for gadget in candidates:
        failures = _constraint_failures(gadget, constraints)
        if failures:
            rejection_counts.update(failures)
            rejected_by[id(gadget)] = failures
        else:
            accepted.append(gadget)
    accepted.sort(key=lambda gadget: synthesis.context_cost(gadget, constraints)["score"])
    return accepted, dict(sorted(rejection_counts.items())), rejected_by


def _constraint_failures(gadget, constraints: dict) -> list[str]:
    semantic = gadget.semantics
    failures = []
    if "arch" in constraints and gadget.arch not in constraints["arch"]:
        failures.append("arch")
    if "modules" in constraints and gadget.module not in constraints["modules"]:
        failures.append("module")
    if "terminator" in constraints and semantic["terminator"] not in constraints["terminator"]:
        failures.append("terminator")

    clobbers = set(semantic["clobbers"])
    preserved = {
        registers.canonical_register(item, gadget.arch)
        for item in constraints.get("preserve", [])
    }
    if clobbers & preserved:
        failures.append("preserve")

    for constraint_name, semantic_name, failure in (
        ("require_reads", "register_reads", "required_read"),
        ("require_writes", "register_writes", "required_write"),
    ):
        required = {
            registers.canonical_register(item, gadget.arch)
            for item in constraints.get(constraint_name, [])
        }
        if not required.issubset(set(semantic[semantic_name])):
            failures.append(failure)

    if "max_stack_delta" in constraints:
        delta = semantic["stack_delta"]
        if delta is None:
            failures.append("dynamic_stack")
        elif abs(delta) > constraints["max_stack_delta"]:
            failures.append("stack_delta")

    forbidden = set(constraints.get("forbid", []))
    forbidden_checks = {
        "call": any(item.startswith("call ") for item in semantic["control_flow"]),
        "flags": semantic["flags_written"] or semantic["flags_read"],
        "jump": any(item.startswith("j") or item.startswith("loop") for item in semantic["control_flow"]),
        "memory_read": bool(semantic["memory_reads"]),
        "memory_write": bool(semantic["memory_writes"]),
        "syscall": any(item.startswith(("int ", "syscall", "sysenter")) for item in semantic["control_flow"]),
        "unknown": bool(semantic["unknown"]),
    }
    for name in sorted(forbidden):
        if name not in forbidden_checks:
            failures.append(f"unsupported_forbid:{name}")
        elif forbidden_checks[name]:
            failures.append(name)
    return failures


def execute_queries(
    console,
    queries,
    formatter,
    with_base_address: bool,
    limit: int | None,
    diagnostics_stream=sys.stderr,
    fields=None,
) -> list[dict]:
    records = []
    for query in queries:
        if isinstance(query, GadgetLookup):
            records.append(_execute_lookup(console, query, formatter, with_base_address, fields))
            continue
        if isinstance(query, Synthesis):
            records.append(_execute_synthesis(
                console, query, formatter, with_base_address, fields,
            ))
            continue
        if isinstance(query, Plan):
            records.append(_execute_plan(
                console, query, formatter, with_base_address,
                diagnostics_stream, fields,
            ))
            continue
        candidates, error = _search_candidates(console, query, diagnostics_stream)
        records.append(_query_record(
            query, candidates, error, formatter, with_base_address, limit, fields,
        ))
    return records


def _execute_lookup(console, lookup, formatter, with_base_address, fields):
    matches = [gadget for gadget in console.gadgets if gadget.identifier == lookup.gadget_id]
    return {
        "schema": "ropcatalog.lookup.v1",
        "id": lookup.identifier,
        "gadget_id": lookup.gadget_id,
        "status": "ok" if matches else "no_match",
        "count": len(matches),
        "gadgets": [gadget_to_record(gadget, formatter, with_base_address, fields) for gadget in matches],
        **({"failure": "gadget_id_not_found"} if not matches else {}),
    }


def _execute_synthesis(console, request, formatter, with_base_address, fields):
    specification = request.specification
    solver = synthesis.Synthesizer(
        console.gadgets,
        _constraint_failures,
        specification["constraints"],
        specification["search"],
        console.semantic_index,
    )
    state, alternatives, expanded, source_rejections = solver.solve(specification)
    if state is None:
        record = {
            "schema": "ropcatalog.synthesis.v1",
            "id": request.identifier,
            "status": "no_match",
            "failure": solver.failure or ("search_exhausted" if expanded >= specification["search"]["max_nodes"] else "no_chain"),
            "search": {**specification["search"], "expanded": expanded},
            "constraints": specification["constraints"],
            "goals": {
                "set": specification["set"], "write": specification["write"],
                "transition": specification["transition"], "call": specification["call"],
            },
        }
        if source_rejections:
            record["rejections"] = source_rejections
        if alternatives:
            record["alternatives"] = alternatives[-3:]
        return record

    chain = synthesis.build_chain(state, specification)
    gadget_records = [
        gadget_to_record(
            gadget, formatter, with_base_address, fields,
            synthesis.context_cost(gadget),
        )
        for gadget in state.gadgets
    ]
    byte_verification = verification.verify_bytes(state.gadgets) if specification["verify"] == "bytes" else {
        "method": "capstone", "status": "not_requested", "executes_target_bytes": False,
    }
    emulation = verification.emulate_chain(
        state.gadgets, chain, solver.desired, specification["scratch"],
    ) if specification["verify"] == "emulate" else {
        "method": "unicorn", "status": "not_requested", "executes_target_bytes": False,
    }
    verification_issues = list(chain["issues"])
    if byte_verification["status"] in {"incomplete", "unavailable"}:
        verification_issues.append(f"byte verification {byte_verification['status']}")
    if emulation["status"] in {"failed", "mismatch", "unavailable"}:
        verification_issues.append(f"emulation {emulation['status']}")
    record = {
        "schema": "ropcatalog.synthesis.v1",
        "id": request.identifier,
        "status": "ok" if not verification_issues else "partial",
        "count": len(state.gadgets),
        "goals": {
            "set": specification["set"], "write": specification["write"],
            "transition": specification["transition"], "call": specification["call"],
        },
        "constraints": specification["constraints"],
        "search": {**specification["search"], "expanded": expanded},
        "gadgets": gadget_records,
        "steps": [
            {
                "gadget_id": gadget.identifier,
                "stack_values": dict(state.stack_inputs[index]),
                "assignments": gadget.semantics["assignments"],
                "before": state.trace[index]["before"],
                "after": state.trace[index]["after"],
                "memory_writes": state.trace[index]["memory_writes"],
                "cost": synthesis.context_cost(gadget),
            }
            for index, gadget in enumerate(state.gadgets)
        ],
        "state": {
            "arch": state.arch,
            "registers": dict(state.values),
            "memory_goals": list(state.memory_goals),
            "control_done": state.control_done,
        },
        "chain": chain,
        "verification": {
            "method": "symbolic-effects-v2",
            "status": "consistent" if not verification_issues else "incomplete",
            "executes_target_bytes": emulation["executes_target_bytes"],
            "issues": verification_issues,
            "bytes": byte_verification,
            "emulation": emulation,
            "proof": {
                "stage": "before_control_transfer" if specification["call"] or specification["transition"] else "chain_end",
                "registers": [
                    {
                        "register": register,
                        "expected": expected,
                        "actual": dict(state.values).get(register),
                        "satisfied": dict(state.values).get(register) == expected,
                    }
                    for register, expected in solver.desired.items()
                ],
                "memory_goals": {
                    "satisfied": list(state.memory_goals),
                    "total": len(specification["write"]),
                },
                "control": {
                    "satisfied": state.control_done,
                    "required": specification["transition"] is not None,
                },
            },
        },
    }
    if specification["emit"]:
        rendered = synthesis.render_chain(chain)
        record["rendered"] = {name: rendered[name] for name in specification["emit"]}
    if alternatives:
        record["alternatives"] = alternatives
    return record


def _search_candidates(console, query, diagnostics_stream) -> tuple[list, str | None]:
    console_input = query.command
    if query.raw_gadget and not query.command.startswith("?"):
        console_input = f"? {query.command}"
    command_name = console_input.split(maxsplit=1)[0].lower()
    if command_name not in console.query_command_names:
        return [], "unrecognized_command"
    real_stdout = sys.stdout
    try:
        sys.stdout = diagnostics_stream
        results = console.execute(console_input)
    except re.error:
        return [], "invalid_regex"
    except SystemExit:
        return [], "command_exited"
    finally:
        sys.stdout = real_stdout
    return sorted(results, key=gadgets.sort_key), None


def _query_record(query, candidates, error, formatter, with_base_address, limit, fields) -> dict:
    results, rejections, rejected_by = _apply_constraints(candidates, query.constraints)
    pareto = _pareto_gadget_ids(results, query.constraints)
    total = len(results)
    if limit is not None:
        results = results[:limit]
    failure = error
    if not failure and not results:
        failure = "no_candidates" if not candidates else "constraints_rejected_all"
    alternatives = []
    if failure == "constraints_rejected_all":
        for gadget in candidates[:3]:
            alternative = gadget_to_record(
                gadget, formatter, with_base_address, fields,
                synthesis.context_cost(gadget, query.constraints),
            )
            alternative["rejected_by"] = rejected_by.get(id(gadget), [])
            alternatives.append(alternative)
    record = {
        "schema": "ropcatalog.query.v1",
        "id": query.identifier,
        "query": query.command,
        "status": "error" if error else ("ok" if results else "no_match"),
        "count": len(results),
        "total": total,
        "truncated": len(results) < total,
        "gadgets": [
            gadget_to_record(
                gadget, formatter, with_base_address, fields,
                synthesis.context_cost(gadget, query.constraints),
            )
            for gadget in results
        ],
    }
    if query.constraints:
        record["constraints"] = query.constraints
    if failure:
        record["failure"] = failure
    if len(candidates) != total:
        record["unfiltered_total"] = len(candidates)
    if rejections:
        record["rejections"] = rejections
    if alternatives:
        record["alternatives"] = alternatives
    record["ranking"] = "contextual-cost-v1"
    if pareto:
        record["pareto"] = pareto
    return record


def _pareto_gadget_ids(candidates, constraints, maximum=8):
    front = []
    for gadget in candidates:
        cost = synthesis.context_cost(gadget, constraints)["components"]
        if any(_dominates(other_cost, cost) for _other, other_cost in front):
            continue
        front = [(other, other_cost) for other, other_cost in front if not _dominates(cost, other_cost)]
        front.append((gadget, cost))
        if len(front) >= maximum:
            break
    return [gadget.identifier for gadget, _cost in front]


def _dominates(left, right):
    return all(left[name] <= right[name] for name in left) and any(left[name] < right[name] for name in left)


def _execute_plan(console, plan, formatter, with_base_address, diagnostics_stream, fields) -> dict:
    selected, selected_gadgets, failed_step = _search_plan(
        console, plan, formatter, with_base_address, diagnostics_stream, fields,
    )

    verification_issues = []
    for selection, gadget in zip(selected, selected_gadgets):
        semantic = gadget.semantics
        if semantic["stack_delta"] is None:
            verification_issues.append(f"step {selection['step']}: dynamic stack delta")
        if semantic["unknown"]:
            verification_issues.append(f"step {selection['step']}: unknown instruction effects")
        if semantic["terminator"] not in {"ret", "retn", "iret", "iretq", "syscall", "sysenter"}:
            verification_issues.append(f"step {selection['step']}: non-chain terminator")

    stack_deltas = [gadget.semantics["stack_delta"] for gadget in selected_gadgets]
    total_stack_delta = None if any(delta is None for delta in stack_deltas) else sum(stack_deltas)
    if plan.alignment and total_stack_delta is not None:
        actual = (plan.alignment["initial"] + total_stack_delta) % plan.alignment["modulus"]
        if actual != plan.alignment["final"]:
            verification_issues.append(f"final stack alignment is {actual}, expected {plan.alignment['final']}")

    plan_state = synthesis.SearchState(
        tuple(selected_gadgets),
        tuple(tuple(sorted(selection["values"].items())) for selection in selected),
        tuple(sorted({name: value for selection in selected for name, value in selection["values"].items()}.items())),
        (), False, selected_gadgets[0].arch if selected_gadgets else None, 0,
    )
    chain = synthesis.build_chain(plan_state, {
        "abi": "none", "bad_bytes": [], "bases": {}, "call": None,
        "filler": "<filler>", "max_words": 256, "mitigations": [], "write": [],
    })
    verification_issues.extend(chain["issues"])

    status = "ok" if failed_step is None else ("partial" if selected else "no_match")
    return {
        "schema": "ropcatalog.plan.v1",
        "id": plan.identifier,
        "status": status,
        "count": len(selected),
        "total": len(plan.steps),
        "gadgets": [
            gadget_to_record(gadget, formatter, with_base_address, fields)
            for gadget in selected_gadgets
        ],
        "steps": selected,
        "failure": failed_step,
        "stack": {
            "alignment": plan.alignment,
            "total_delta": total_stack_delta,
        },
        "chain": chain,
        "verification": {
            "method": "syntactic-effects-v1",
            "status": "consistent" if failed_step is None and not verification_issues else "incomplete",
            "executes_target_bytes": False,
            "issues": verification_issues,
        },
    }


def _extra_stack_bytes(gadget) -> int | None:
    delta = gadget.semantics["stack_delta"]
    if delta is None:
        return None
    word_size = 8 if gadget.arch == "x64" else 4
    expected = word_size * (len(gadget.semantics["stack_pops"]) + 1)
    return delta - expected


def interface_contract() -> dict:
    return {
        "schema": "ropcatalog.capabilities.v1",
        "inputs": ["rp++", "ROPgadget", "Ropper", "ropcatalog.catalog.v1"],
        "queries": {
            "exact": {"argument": "--query", "repeatable": True},
            "semantic": {
                "argument": "--command",
                "commands": sorted(terminal.Terminal.SUPPORTED_QUERY_COMMANDS),
                "modifiers": ["/n", "/v"],
            },
            "batch": {
                "argument": "--batch",
                "record_keys": ["id", "query|command|plan|synthesize|gadget_id"],
            },
            "serve": {"argument": "--serve", "transport": "JSONL standard input/output"},
        },
        "synthesis": {
            "goals": ["set", "write", "transition", "call", "postconditions"],
            "profiles": sorted(synthesis.ABI_ARGUMENTS),
            "mitigations": ["cet", "cfg", "kpti", "smap", "smep"],
            "search": ["beam_width", "max_depth", "max_nodes", "per_effect"],
            "outputs": ["chain words", "stack frames", "python", "pwntools"],
            "stable_references": ["gadget_id", "locked"],
        },
        "constraints": [
            "arch", "forbid", "max_stack_delta", "modules", "preserve",
            "require_reads", "require_writes", "terminator",
        ],
        "address_kinds": ["unknown", "rva", "va"],
        "semantic_architectures": ["x86", "x64"],
        "forbid_values": [
            "call", "flags", "jump", "memory_read", "memory_write",
            "syscall", "unknown",
        ],
        "gadget_fields": [
            "id", "source_id", "source_sha256", "extractor", "extractor_version", "module",
            "address", "address_kind", "arch", "bytes", "raw", "instructions", "semantics",
            "formatted", "cost",
        ],
        "outputs": [
            "ropcatalog.query.v1", "ropcatalog.lookup.v1", "ropcatalog.plan.v1",
            "ropcatalog.synthesis.v1", "ropcatalog.catalog.v1",
        ],
        "verification": {
            "levels": ["syntactic", "capstone", "unicorn"],
            "can_execute_target_bytes": True,
        },
    }


def write_jsonl(records: list[dict], stream) -> None:
    for record in records:
        print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=stream)


def serve_requests(console, formatter, with_base_address, limit, fields) -> int:
    for line_number, line in enumerate(sys.stdin, 1):
        if not line.strip():
            continue
        try:
            query = _parse_batch_line(line, line_number)
            if query is None:
                continue
            records = execute_queries(
                console, [query], formatter, with_base_address, limit,
                diagnostics_stream=io.StringIO(), fields=fields,
            )
        except ValueError as error:
            records = [{
                "schema": "ropcatalog.error.v1",
                "id": str(line_number),
                "status": "error",
                "failure": str(error),
            }]
        write_jsonl(records, sys.stdout)
        sys.stdout.flush()
    return 0


def write_module_artifacts(records: list[dict], artifact_dir: Path, modules: set[str]) -> list[Path]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for module in sorted(modules):
        safe_module = re.sub(r"[^A-Za-z0-9_.-]", "_", module)
        path = artifact_dir / f"{safe_module}.ropcatalog.jsonl"
        module_records = []
        for record in records:
            module_record = dict(record)
            module_record["module"] = module
            module_record["gadgets"] = [
                gadget for gadget in record["gadgets"] if gadget["module"] == module
            ]
            module_record["count"] = len(module_record["gadgets"])
            module_records.append(module_record)
        with path.open("w", encoding="utf-8") as stream:
            write_jsonl(module_records, stream)
        paths.append(path)
    return paths


def main() -> int:

    parser = build_parser()
    args = parser.parse_args()

    if args.capabilities:
        print(json.dumps(interface_contract(), separators=(",", ":"), sort_keys=True))
        return 0

    noninteractive = (
        args.command is not None
        or bool(args.query)
        or args.batch is not None
        or args.catalog_out is not None
        or args.serve
    )

    # In command mode, redirect loading messages to stderr so only
    # gadget output goes to stdout (clean for piping/redirection)
    if noninteractive:
        real_stdout = sys.stdout
        diagnostics_stream = io.StringIO() if (
            args.artifact_dir or args.serve or (args.jsonl and not args.verbose)
        ) else sys.stderr
        sys.stdout = diagnostics_stream

    bad_chars = None
    if args.bad_characters:
        bad_chars = utils.format_bad_chars(args.bad_characters)
        print(f"[+] Bad characters: {bad_chars}")

    # Collect files from both file and directory paths
    file_paths = []
    input_stream = None
    for path_str in args.paths:
        if path_str == "-":
            input_stream = sys.stdin
            continue
        path = Path(path_str).resolve()

        if path.is_dir():
            # Add all files in the directory
            file_paths.extend(sorted(file for file in path.iterdir() if file.is_file()))
        elif path.is_file():
            file_paths.append(path)
        else:
            if noninteractive:
                sys.stdout = real_stdout
            print(f"[!] Path '{path}' is not a valid file or directory.", file=sys.stderr if noninteractive else sys.stdout)
            return 1

    # Check if any files were found
    if not file_paths and input_stream is None:
        if noninteractive:
            sys.stdout = real_stdout
        output = sys.stderr if noninteractive else sys.stdout
        print("[!] No files found in the specified path(s).", file=output)
        print("[!] Make sure the directory contains gadget files.", file=output)
        return 1

    print(f"[+] Found {len(file_paths) + int(input_stream is not None)} source(s) to parse")

    try:
        catalog = gadgets.Gadgets(
            file_paths=file_paths,
            bad_chars=bad_chars,
            encoding=args.encoding,
            input_stream=input_stream,
            input_module=args.stdin_module or "stdin",
            address_kind=args.address_kind,
        )
    except (OSError, ValueError) as error:
        if noninteractive:
            sys.stdout = real_stdout
        print(f"[!] {error}", file=sys.stderr)
        return 1

    if noninteractive:
        sys.stdout = real_stdout

    if catalog.full_count == 0:
        print("[!] No gadgets available, try another module", file=sys.stderr if noninteractive else sys.stdout)
        return 1

    if args.catalog_out:
        count = catalog.write_catalog(args.catalog_out)
        print(f"[+] Wrote {count} gadget(s): {args.catalog_out}", file=sys.stderr)
        return 0

    if args.offset and any(gadget.address_kind == "va" for gadget in catalog.gadgets):
        print("[!] Cannot rebase catalog addresses marked as virtual addresses.", file=sys.stderr)
        return 1

    # Disable uniqueness if --all flag is set
    if args.all:
        catalog.set_uniqueness(False)

    style_map = {
        "plain": formatters.PlainFormatter,
        "python": formatters.PythonFormatter,
        "cpp": formatters.CppFormatter,
        "js": formatters.JavaScriptFormatter,
    }

    formatter = style_map[args.style]()

    console = terminal.Terminal(catalog, formatter=formatter, with_base_address=args.offset)

    if args.serve:
        return serve_requests(console, formatter, args.offset, args.limit, args.fields)

    if args.command and not args.jsonl and args.limit is None:
        return console.run_command(args.command)

    queries = []
    if args.command:
        queries.append(Query("1", args.command))
    queries.extend(
        Query(str(index), query, True)
        for index, query in enumerate(args.query, len(queries) + 1)
    )
    if args.batch:
        try:
            queries.extend(parse_batch_queries(args.batch))
        except ValueError as error:
            print(f"[!] {error}", file=sys.stderr)
            return 1

    if queries:
        records = execute_queries(
            console,
            queries,
            formatter,
            args.offset,
            args.limit,
            diagnostics_stream,
            args.fields,
        )
        if args.jsonl:
            if args.artifact_dir:
                modules = {gadget.module for gadget in catalog.gadgets}
                for path in write_module_artifacts(records, args.artifact_dir, modules):
                    print(f"[+] Wrote {len(records)} query result(s): {path}", file=sys.stderr)
            else:
                write_jsonl(records, sys.stdout)
        else:
            for record in records:
                print(f"== [{record['id']}] {record['query']} ==")
                for gadget in record["gadgets"]:
                    print(gadget["formatted"])
                print(f"---- {record['count']} gadget(s)", file=sys.stderr)
        return 0

    return console.start()

def _search_plan(console, plan, formatter, with_base_address, diagnostics_stream, fields):
    prepared = []
    for step_number, step in enumerate(plan.steps, 1):
        constraints = dict(step.constraints)
        constraints["require_writes"] = sorted(set(constraints.get("require_writes", [])) | set(step.values))
        constraints["forbid"] = sorted(set(constraints.get("forbid", [])) | {"unknown"})
        if "terminator" not in constraints:
            constraints["terminator"] = ["ret", "retn"] if step_number < len(plan.steps) else [
                "iret", "iretq", "ret", "retn", "syscall", "sysenter",
            ]
        query = Query(str(step_number), step.command, step.raw_gadget, constraints)
        candidates, error = _search_candidates(console, query, diagnostics_stream)
        if error:
            return [], [], _query_record(query, candidates, error, formatter, with_base_address, 1, fields)
        prepared.append((step_number, step, constraints, candidates))

    nodes = 0
    best = ([], [], None, set())

    def visit(index, selected, selected_gadgets, selected_arch, live_values):
        nonlocal nodes, best
        if len(selected) > len(best[0]):
            best = (selected, selected_gadgets, selected_arch, live_values)
        if index == len(prepared):
            return selected, selected_gadgets
        if nodes >= 5000:
            return None
        step_number, step, base_constraints, candidates = prepared[index]
        step_registers = {
            registers.canonical_register(name, selected_arch or "x64") for name in step.values
        }
        constraints = dict(base_constraints)
        constraints["preserve"] = sorted(set(constraints.get("preserve", [])) | (live_values - step_registers))
        if selected_arch:
            constraints["arch"] = [selected_arch]
        candidates = sorted(candidates, key=lambda gadget: synthesis.context_sort_key(gadget, constraints))
        for gadget in candidates[:64]:
            nodes += 1
            if _constraint_failures(gadget, constraints):
                continue
            canonical_values = {
                registers.canonical_register(name, gadget.arch): value
                for name, value in step.values.items()
            }
            canonical_live = {registers.canonical_register(name, gadget.arch) for name in live_values}
            next_live = canonical_live - set(gadget.semantics["clobbers"])
            next_live.update(canonical_values)
            selection = {
                "step": step_number,
                "command": step.command,
                "constraints": constraints,
                "values": canonical_values,
                "auto_preserve": sorted(canonical_live - set(canonical_values)),
                "gadget_index": len(selected_gadgets),
                "stack": {
                    "delta": gadget.semantics["stack_delta"],
                    "extra_bytes": _extra_stack_bytes(gadget),
                    "pops": [
                        {"register": name, "value": canonical_values.get(name, "<filler>")}
                        for name in gadget.semantics["stack_pops"]
                    ],
                },
            }
            result = visit(
                index + 1,
                selected + [selection],
                selected_gadgets + [gadget],
                gadget.arch,
                next_live,
            )
            if result is not None:
                return result
        return None

    result = visit(0, [], [], None, set())
    if result is not None:
        return result[0], result[1], None
    selected, selected_gadgets, selected_arch, live_values = best
    if len(selected) == len(prepared):
        return selected, selected_gadgets, None
    step_number, step, constraints, candidates = prepared[len(selected)]
    constraints = dict(constraints)
    constraints["preserve"] = sorted(set(constraints.get("preserve", [])) | live_values)
    if selected_arch:
        constraints["arch"] = [selected_arch]
    query = Query(str(step_number), step.command, step.raw_gadget, constraints)
    return selected, selected_gadgets, _query_record(
        query, candidates, None, formatter, with_base_address, 1, fields,
    )
