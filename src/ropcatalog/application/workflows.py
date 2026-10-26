"""Application workflows for gadget retrieval and exploit planning."""

# Built-in imports
from collections import Counter
from collections.abc import Sequence
import re
import sys
from typing import Any, TextIO

# Local library imports
from ..core import gadgets
from ..core import registers
from ..core import synthesis
from ..core import verification
from ..interface import formatters
from ..interface import terminal
from .requests import BatchRequest, GadgetLookup, Plan, Query, Synthesis

def gadget_to_record(
    gadget: gadgets.Gadget,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    fields: tuple[str, ...] | None = None,
    cost: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize one gadget for JSONL output.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        fields: Optional JSONL gadget fields to retain.
        cost: Precomputed context-sensitive gadget cost, if available.

    Returns:
        Machine-readable gadget record containing the selected fields.
    """
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


def _apply_constraints(
    candidates: list[gadgets.Gadget], constraints: dict[str, Any]
) -> tuple[list[gadgets.Gadget], dict[str, int], dict[int, list[str]]]:
    """Filter candidates and retain deterministic rejection evidence.

    Args:
        candidates: Candidate gadgets to filter, rank, or serialize.
        constraints: Semantic filters and context-sensitive ranking constraints.

    Returns:
        Accepted gadgets, rejection counts, and failures per rejected object.
    """
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


def _constraint_failures(
    gadget: gadgets.Gadget, constraints: dict[str, Any]
) -> list[str]:
    """Return every constraint violated by a gadget.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        constraints: Semantic filters and context-sensitive ranking constraints.

    Returns:
        Constraint names violated by the gadget.
    """
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
    console: terminal.Terminal,
    queries: Sequence[BatchRequest],
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    limit: int | None,
    diagnostics_stream: TextIO = sys.stderr,
    fields: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Execute validated requests against a loaded catalog.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        queries: Validated lookup, query, plan, or synthesis requests.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        limit: Maximum number of gadgets to emit per request.
        diagnostics_stream: Stream receiving non-result diagnostics.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        One result record for every input request.
    """
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


def _execute_lookup(
    console: terminal.Terminal,
    lookup: GadgetLookup,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    fields: tuple[str, ...] | None,
) -> dict[str, Any]:
    """Retrieve a gadget by stable identifier.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        lookup: Stable gadget-ID lookup request.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Stable-ID lookup record.
    """
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


def _execute_synthesis(
    console: terminal.Terminal,
    request: Synthesis,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    fields: tuple[str, ...] | None,
) -> dict[str, Any]:
    """Search, serialize, and optionally verify a synthesis request.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        request: Decoded JSON request object.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Synthesis result with chain and verification evidence when solved.
    """
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


def _search_candidates(
    console: terminal.Terminal, query: Query, diagnostics_stream: TextIO
) -> tuple[list[gadgets.Gadget], str | None]:
    """Run one retrieval request while isolating routine diagnostics.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        query: Validated request to execute or serialize.
        diagnostics_stream: Stream receiving non-result diagnostics.

    Returns:
        Candidate gadgets and an optional command error.
    """
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


def _query_record(
    query: Query,
    candidates: list[gadgets.Gadget],
    error: str | None,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    limit: int | None,
    fields: tuple[str, ...] | None,
) -> dict[str, Any]:
    """Build a bounded query result with ranking and alternatives.

    Args:
        query: Validated request to execute or serialize.
        candidates: Candidate gadgets to filter, rank, or serialize.
        error: Failure reported while executing the request.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        limit: Maximum number of gadgets to emit per request.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Bounded query result including rank, cost, and alternatives.
    """
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


def _pareto_gadget_ids(
    candidates: list[gadgets.Gadget],
    constraints: dict[str, Any],
    maximum: int = 8,
) -> list[str]:
    """Return non-dominated candidate IDs for side-effect tradeoffs.

    Args:
        candidates: Candidate gadgets to filter, rank, or serialize.
        constraints: Semantic filters and context-sensitive ranking constraints.
        maximum: Maximum number of alternatives to return.

    Returns:
        Stable IDs of non-dominated alternatives.
    """
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


def _dominates(left: dict[str, int], right: dict[str, int]) -> bool:
    """Return whether the left cost vector Pareto-dominates the right.

    Args:
        left: Left side-effect cost vector.
        right: Right side-effect cost vector.

    Returns:
        True if the left vector is no worse in every dimension and better in one.
    """
    return all(left[name] <= right[name] for name in left) and any(left[name] < right[name] for name in left)


def _execute_plan(
    console: terminal.Terminal,
    plan: Plan,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    diagnostics_stream: TextIO,
    fields: tuple[str, ...] | None,
) -> dict[str, Any]:
    """Resolve a fixed sequence of dependent gadget goals.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        plan: Fixed sequence of gadget goals.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        diagnostics_stream: Stream receiving non-result diagnostics.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Resolved plan record or deterministic failure evidence.
    """
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


def _extra_stack_bytes(gadget: gadgets.Gadget) -> int | None:
    """Return stack adjustment bytes beyond pops and the return address.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.

    Returns:
        Additional stack adjustment, or ``None`` for dynamic deltas.
    """
    delta = gadget.semantics["stack_delta"]
    if delta is None:
        return None
    word_size = 8 if gadget.arch == "x64" else 4
    expected = word_size * (len(gadget.semantics["stack_pops"]) + 1)
    return delta - expected


def _search_plan(
    console: terminal.Terminal,
    plan: Plan,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    diagnostics_stream: TextIO,
    fields: tuple[str, ...] | None,
) -> tuple[list[dict[str, Any]], list[gadgets.Gadget], dict[str, Any] | None]:
    """Backtrack over fixed-plan steps while preserving live values.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        plan: Fixed sequence of gadget goals.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        diagnostics_stream: Stream receiving non-result diagnostics.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Serialized steps, chosen gadgets, and optional failure evidence.
    """
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

    def visit(
        index: int,
        selected: list[dict[str, Any]],
        selected_gadgets: list[gadgets.Gadget],
        selected_arch: str | None,
        live_values: set[str],
    ) -> tuple[list[dict[str, Any]], list[gadgets.Gadget]] | None:
        """Depth-first search a compatible gadget for each plan step.

        Args:
            index: Index of the next plan step to resolve.
            selected: Serialized plan steps selected so far.
            selected_gadgets: Plan gadgets selected so far.
            selected_arch: Architecture fixed by preceding plan steps.
            live_values: Register values that subsequent plan steps must preserve.

        Returns:
            Completed plan state, or ``None`` when the branch cannot satisfy all steps.
        """
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
