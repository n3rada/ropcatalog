# Built-in imports
import argparse
from collections import Counter
from dataclasses import dataclass, field
import hashlib
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
        "address", "address_kind", "arch", "bytes", "formatted", "id", "instructions", "module",
        "raw", "semantics", "source_id",
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
    if sum((has_query, has_command, has_plan)) != 1:
        raise ValueError(
            f"batch line {line_number} requires exactly one of 'query', 'command', or 'plan'"
        )
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


def gadget_to_record(gadget, formatter, with_base_address: bool, fields=None) -> dict:
    identity = f"{gadget.source_id}\0{gadget.arch}\0{gadget.address}\0{gadget.raw}"
    record = {
        "id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "source_id": gadget.source_id,
        "module": gadget.module,
        "address": gadget.address,
        "address_kind": gadget.address_kind,
        "arch": gadget.arch,
        "bytes": gadget.bytes_hex,
        "instructions": gadget.instructions,
        "semantics": gadget.semantics,
        "raw": gadget.raw,
        "formatted": formatter.format(gadget, with_base_address),
    }
    if gadget.bytes_hex is None:
        record.pop("bytes")
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
        "flags": semantic["flags_written"],
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
    total = len(results)
    if limit is not None:
        results = results[:limit]
    failure = error
    if not failure and not results:
        failure = "no_candidates" if not candidates else "constraints_rejected_all"
    alternatives = []
    if failure == "constraints_rejected_all":
        for gadget in candidates[:3]:
            alternative = gadget_to_record(gadget, formatter, with_base_address, fields)
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
            gadget_to_record(gadget, formatter, with_base_address, fields)
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
    return record


def _execute_plan(console, plan, formatter, with_base_address, diagnostics_stream, fields) -> dict:
    selected = []
    selected_gadgets = []
    live_registers = set()
    selected_arch = None
    failed_step = None
    for step_number, step in enumerate(plan.steps, 1):
        constraints = dict(step.constraints)
        step_registers = {
            registers.canonical_register(name, "x64") for name in step.values
        } | {
            registers.canonical_register(name, "x86") for name in step.values
        }
        auto_preserve = sorted(live_registers - step_registers)
        constraints["preserve"] = sorted(set(constraints.get("preserve", [])) | set(auto_preserve))
        constraints["require_writes"] = sorted(set(constraints.get("require_writes", [])) | set(step.values))
        constraints["forbid"] = sorted(set(constraints.get("forbid", [])) | {"unknown"})
        if "terminator" not in constraints:
            constraints["terminator"] = ["ret", "retn"] if step_number < len(plan.steps) else [
                "iret", "iretq", "ret", "retn", "syscall", "sysenter",
            ]
        if selected_arch:
            constraints["arch"] = [selected_arch]
        query = Query(str(step_number), step.command, step.raw_gadget, constraints)
        candidates, error = _search_candidates(console, query, diagnostics_stream)
        result = _query_record(query, candidates, error, formatter, with_base_address, 1, fields)
        if result["status"] != "ok":
            failed_step = result
            break
        gadget = next(candidate for candidate in candidates if not _constraint_failures(candidate, constraints))
        selected_arch = gadget.arch
        canonical_values = {
            registers.canonical_register(name, gadget.arch): value
            for name, value in step.values.items()
        }
        live_registers = {
            registers.canonical_register(name, gadget.arch)
            for name in live_registers
        }
        live_registers.difference_update(gadget.semantics["clobbers"])
        live_registers.update(canonical_values)
        selected_gadgets.append(gadget)
        selected.append({
            "step": step_number,
            "command": step.command,
            "constraints": constraints,
            "values": canonical_values,
            "auto_preserve": auto_preserve,
            "gadget_index": len(selected_gadgets) - 1,
            "stack": {
                "delta": gadget.semantics["stack_delta"],
                "extra_bytes": _extra_stack_bytes(gadget),
                "pops": [
                    {"register": name, "value": canonical_values.get(name, "<filler>")}
                    for name in gadget.semantics["stack_pops"]
                ],
            },
        })

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
            "semantic": {"argument": "--command"},
            "batch": {
                "argument": "--batch",
                "record_keys": ["id", "query|command|plan", "constraints"],
            },
            "serve": {"argument": "--serve", "transport": "JSONL standard input/output"},
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
            "id", "source_id", "module", "address", "address_kind", "arch", "bytes", "raw",
            "instructions", "semantics", "formatted",
        ],
        "outputs": [
            "ropcatalog.query.v1", "ropcatalog.plan.v1", "ropcatalog.catalog.v1",
        ],
        "verification": {"level": "syntactic", "executes_target_bytes": False},
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
