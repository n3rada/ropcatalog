from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
import re
from typing import Any

from . import registers
from .gadgets import Gadget


ABI_ARGUMENTS = {
    "none": (),
    "windows-x64": ("rcx", "rdx", "r8", "r9"),
    "windows-x64-kernel": ("rcx", "rdx", "r8", "r9"),
    "sysv-x64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "x86-cdecl": (),
}
ABI_CLOBBERS = {
    "none": (),
    "windows-x64": ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"),
    "windows-x64-kernel": ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"),
    "sysv-x64": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"),
    "x86-cdecl": ("eax", "ecx", "edx"),
}
SUPPORTED_CONTROLS = {"call", "iret", "iretd", "iretq", "jmp", "ret", "retn", "syscall", "sysenter", "sysret"}


@dataclass(frozen=True)
class SearchState:
    gadgets: tuple[Gadget, ...]
    stack_inputs: tuple[tuple[tuple[str, str], ...], ...]
    values: tuple[tuple[str, str], ...]
    memory_goals: tuple[int, ...]
    control_done: bool
    arch: str | None
    cost: int
    trace: tuple[dict[str, Any], ...] = ()


class SemanticIndex:
    def __init__(self, gadget_list: Sequence[Gadget]) -> None:
        """Index gadget effects for bounded candidate retrieval.

        Args:
            gadget_list: Gadgets in catalog or execution order.
        """
        self.by_write = defaultdict(list)
        self.stack_write = defaultdict(list)
        self.by_move = defaultdict(list)
        self.memory_write = defaultdict(list)
        self.controls = defaultdict(list)
        for gadget in gadget_list:
            for target, effect in gadget.semantics["assignments"].items():
                self.by_write[target].append(gadget)
                if effect.get("kind") == "stack":
                    self.stack_write[target].append(gadget)
                if effect.get("kind") == "register":
                    self.by_move[target, effect["value"]].append(gadget)
            for effect in gadget.semantics["memory_effects"]["writes"]:
                self.memory_write[normalize_address(effect["address"])].append(gadget)
            for effect in gadget.semantics["control_effects"]:
                self.controls[effect["kind"]].append(gadget)
        self.gadgets = tuple(gadget_list)
        for mapping in (self.by_write, self.stack_write, self.by_move, self.memory_write, self.controls):
            for key in mapping:
                mapping[key].sort(key=context_sort_key)

    def candidates(
        self,
        state: SearchState,
        desired: dict[str, str],
        memory_goals: list[dict[str, Any]],
        transition: dict[str, Any] | None,
        per_effect: int,
    ) -> list[Gadget]:
        """Return bounded gadgets that can advance an unsatisfied goal.

        Args:
            state: Immutable synthesis state before the operation.
            desired: Required final register values.
            memory_goals: Required symbolic memory writes.
            transition: Required final control-flow transition.
            per_effect: Maximum indexed candidates retained per effect.

        Returns:
            Matching gadgets in active catalog order.
        """
        values = dict(state.values)
        options = {}
        missing = [target for target, value in desired.items() if values.get(target) != value]
        for target in missing:
            for gadget in self._accepted(self.by_write[target])[:per_effect]:
                options[gadget.identifier] = gadget
            for (destination, source), gadgets_for_move in self.by_move.items():
                if destination != target or values.get(source) == desired[target]:
                    continue
                for gadget in self._accepted(self.stack_write[source])[:per_effect]:
                    options[gadget.identifier] = gadget
        for goal_number, goal in enumerate(memory_goals):
            if goal_number in state.memory_goals:
                continue
            write_gadgets = self._accepted(self.memory_write[normalize_address(goal["address"])])
            for gadget in write_gadgets[:per_effect]:
                options[gadget.identifier] = gadget
                if isinstance(goal["value"], dict):
                    continue
                for effect in gadget.semantics["memory_effects"]["writes"]:
                    source = effect["value"]
                    if normalize_address(effect["address"]) == normalize_address(goal["address"]) and source.get("kind") == "register":
                        for setter in self._accepted(self.stack_write[source["value"]])[:per_effect]:
                            options[setter.identifier] = setter
        if transition and not missing and len(state.memory_goals) == len(memory_goals):
            for gadget in self._accepted(self.controls[transition["kind"]])[:per_effect]:
                options[gadget.identifier] = gadget
        return sorted(options.values(), key=lambda gadget: context_sort_key(gadget, {"live_values": values}))

    def configure(self, accepted_ids: set[str]) -> None:
        """Restrict candidate retrieval to gadgets accepted by constraints.

        Args:
            accepted_ids: Stable gadget IDs accepted by the active constraints.
        """
        self.accepted_ids = accepted_ids

    def _accepted(self, values: Iterable[Gadget]) -> list[Gadget]:
        """Filter indexed gadgets through the configured accepted-ID set.

        Args:
            values: Known symbolic register or stack values.

        Returns:
            Matching gadgets in active catalog order.
        """
        return [gadget for gadget in values if gadget.identifier in self.accepted_ids]


class Synthesizer:
    def __init__(
        self,
        gadget_list: Sequence[Gadget],
        constraint_failures: Callable[[Gadget, dict[str, Any]], list[str]],
        constraints: dict[str, Any],
        search: dict[str, int],
        index: SemanticIndex | None = None,
    ) -> None:
        """Configure bounded semantic chain search over accepted gadgets.

        Args:
            gadget_list: Gadgets in catalog or execution order.
            constraint_failures: Callback returning failed constraints for a gadget.
            constraints: Semantic filters and context-sensitive ranking constraints.
            search: Bounded search parameters.
            index: Semantic gadget index used to infer usable register sources.
        """
        self.constraints = constraints
        self.constraint_failures = constraint_failures
        self.max_nodes = search["max_nodes"]
        self.beam_width = search["beam_width"]
        self.max_depth = search["max_depth"]
        self.per_effect = search["per_effect"]
        self.index = index or SemanticIndex(gadget_list)
        accepted_ids = set()
        rejection_counts = defaultdict(int)
        for gadget in gadget_list:
            failures = constraint_failures(gadget, constraints)
            if failures:
                for failure in failures:
                    rejection_counts[failure] += 1
            else:
                accepted_ids.add(gadget.identifier)
        self.index.configure(accepted_ids)
        self.rejections = dict(sorted(rejection_counts.items()))
        self.by_id = {gadget.identifier: gadget for gadget in self.index.gadgets if gadget.identifier in accepted_ids}
        self.failure = None

    def solve(
        self,
        specification: dict[str, Any],
    ) -> tuple[SearchState | None, list[dict[str, Any]], int, dict[str, int]]:
        """Search for a minimum-cost chain satisfying the specification.

        Args:
            specification: Normalized chain synthesis specification.

        Returns:
            Best solved state, bounded alternatives, expanded-node count, and rejection counts.
        """
        abi = specification["abi"]
        available_arches = sorted({gadget.arch for gadget in self.index.gadgets})
        constrained_arches = specification["constraints"].get("arch", [])
        if len(constrained_arches) == 1:
            goal_arch = constrained_arches[0]
        elif len(available_arches) == 1:
            goal_arch = available_arches[0]
        else:
            goal_arch = "x64" if any(registers.is_register(name, "x64") and not registers.is_register(name, "x86") for name in specification["set"]) else "x86"
        desired = {
            registers.canonical_register(name, goal_arch): normalize_value(value)
            for name, value in specification["set"].items()
        }
        call = specification.get("call")
        if call:
            for register, value in zip(ABI_ARGUMENTS[abi], call.get("arguments", [])):
                desired.setdefault(register, normalize_value(value))
        memory_goals = specification["write"]
        memory_seed_values = infer_memory_values(desired, memory_goals, specification["scratch"], self.index, goal_arch)
        self.desired = desired
        transition = specification.get("transition")
        seed_values = {**memory_seed_values, **dependency_closure(desired, self.index.by_move)}
        initial = SearchState((), (), (), (), False, None, 0)
        for gadget_id in specification["locked"]:
            gadget = self.by_id.get(gadget_id)
            if gadget is None:
                self.failure = f"locked_gadget_not_found:{gadget_id}"
                return None, [], 0, self.rejections
            initial = apply_gadget(initial, gadget, desired, memory_goals, transition, seed_values)
            if initial is None:
                self.failure = f"locked_gadget_invalid:{gadget_id}"
                return None, [], 0, self.rejections
        frontier = [initial]
        seen = {state_key(initial)}
        expanded = 0
        alternatives = []

        for _depth in range(self.max_depth + 1):
            completed = [state for state in frontier if complete(state, desired, memory_goals, transition)]
            if completed:
                completed.sort(key=lambda state: (state.cost, tuple(gadget.identifier for gadget in state.gadgets)))
                alternatives = [
                    {"gadget_ids": [gadget.identifier for gadget in state.gadgets], "cost": state.cost}
                    for state in completed[1:4]
                ]
                return completed[0], alternatives, expanded, self.rejections
            next_frontier = []
            for state in frontier:
                for gadget in self.index.candidates(state, desired, memory_goals, transition, self.per_effect):
                    if expanded >= self.max_nodes:
                        return None, alternatives, expanded, self.rejections
                    expanded += 1
                    if state.arch and gadget.arch != state.arch:
                        continue
                    next_state = apply_gadget(state, gadget, desired, memory_goals, transition, seed_values)
                    if next_state is None:
                        continue
                    key = state_key(next_state)
                    if key in seen:
                        continue
                    seen.add(key)
                    next_frontier.append(next_state)
            next_frontier.sort(key=lambda state: state.cost + heuristic(state, desired, memory_goals, transition))
            frontier = next_frontier[:self.beam_width]
            if not frontier:
                break
        return None, alternatives, expanded, self.rejections


def apply_gadget(
    state: SearchState,
    gadget: Gadget,
    desired: dict[str, str],
    memory_goals: list[dict[str, Any]],
    transition: dict[str, Any] | None,
    seed_values: dict[str, str] | None = None,
) -> SearchState | None:
    """Apply modeled gadget effects to one immutable search state.

    Args:
        state: Immutable synthesis state before the operation.
        gadget: Gadget to inspect, rank, format, or apply.
        desired: Required final register values.
        memory_goals: Required symbolic memory writes.
        transition: Required final control-flow transition.
        seed_values: Known register values at the start of the search.

    Returns:
        Next immutable state, or ``None`` when the gadget is incompatible or loses progress.
    """
    semantics = gadget.semantics
    if semantics["stack_delta"] is None or semantics["unknown"]:
        return None
    if transition and any(effect["kind"] == transition["kind"] for effect in semantics["control_effects"]):
        if not transition_matches(gadget, transition):
            return None
    elif semantics["terminator"] not in {"ret", "retn"}:
        return None

    before_values = dict(state.values)
    values = dict(before_values)
    assignments = semantics["assignments"]
    stack_inputs = {}
    dependencies = {**(seed_values or {}), **dependency_values(desired, values, assignments)}
    for target, effect in assignments.items():
        if effect.get("kind") == "stack":
            selected = desired.get(target, dependencies.get(target))
            if selected is not None:
                stack_inputs[target] = selected

    for clobber in semantics["clobbers"]:
        values.pop(clobber, None)
    xchg_registers = set()
    for instruction in gadget.instructions:
        if instruction.startswith("xchg "):
            left, right = [part.strip() for part in instruction[5:].split(",", 1)]
            if registers.is_register(left, gadget.arch) and registers.is_register(right, gadget.arch):
                left = registers.canonical_register(left, gadget.arch)
                right = registers.canonical_register(right, gadget.arch)
                left_value = before_values.get(left)
                right_value = before_values.get(right)
                if right_value is None:
                    values.pop(left, None)
                else:
                    values[left] = right_value
                if left_value is None:
                    values.pop(right, None)
                else:
                    values[right] = left_value
                xchg_registers.update({left, right})

    for target, effect in assignments.items():
        if target in xchg_registers:
            continue
        value = evaluate(effect, values, stack_inputs.get(target))
        if value is None:
            values.pop(target, None)
        else:
            values[target] = value

    completed_memory = set(state.memory_goals)
    for goal_number, goal in enumerate(memory_goals):
        if goal_number in completed_memory:
            continue
        for effect in semantics["memory_effects"]["writes"]:
            if memory_matches(effect, goal, values, gadget.arch):
                completed_memory.add(goal_number)
                break

    control_done = state.control_done
    if transition and transition_matches(gadget, transition):
        control_done = True

    old_progress = satisfaction(state, desired, memory_goals, transition)
    new_state = SearchState(
        state.gadgets + (gadget,),
        state.stack_inputs + (tuple(sorted(stack_inputs.items())),),
        tuple(sorted(values.items())),
        tuple(sorted(completed_memory)),
        control_done,
        gadget.arch,
        state.cost + context_cost(gadget, {"live_values": before_values})["score"],
        state.trace + ({
            "before": dict(sorted(before_values.items())),
            "after": dict(sorted(values.items())),
            "memory_writes": semantics["memory_effects"]["writes"],
        },),
    )
    if satisfaction(new_state, desired, memory_goals, transition) < old_progress:
        return None
    return new_state


def dependency_values(
    desired: dict[str, str],
    values: dict[str, str],
    assignments: dict[str, dict[str, Any]],
) -> dict[str, str]:
    """Propagate desired values backward through register assignments.

    Args:
        desired: Required final register values.
        values: Known symbolic register or stack values.
        assignments: Symbolic register assignments to update.

    Returns:
        Source-register values required by unresolved direct assignments.
    """
    needed = {}
    for target, goal_value in desired.items():
        if values.get(target) == goal_value:
            continue
        effect = assignments.get(target)
        if effect and effect.get("kind") == "register":
            needed[effect["value"]] = goal_value
    return needed


def dependency_closure(
    desired: dict[str, str],
    moves: dict[tuple[str, str], list[Gadget]],
) -> dict[str, str]:
    """Compute register-value prerequisites reachable through move gadgets.

    Args:
        desired: Required final register values.
        moves: Available destination-to-source register moves.

    Returns:
        Desired values propagated transitively to reachable source registers.
    """
    needed = dict(desired)
    changed = True
    while changed:
        changed = False
        for destination, source in moves:
            if destination in needed and source not in needed:
                needed[source] = needed[destination]
                changed = True
    return needed


def infer_memory_values(
    desired: dict[str, str],
    memory_goals: list[dict[str, Any]],
    scratch: list[str],
    index: SemanticIndex,
    arch: str,
) -> dict[str, str]:
    """Infer pointer and value registers required by memory-write goals.

    Args:
        desired: Required final register values.
        memory_goals: Required symbolic memory writes.
        scratch: Candidate writable addresses used by the requested chain.
        index: Semantic gadget index used to infer usable register sources.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Pointer and source-register seed values inferred from write goals.
    """
    seeds = {}
    for goal_number, goal in enumerate(memory_goals):
        if scratch:
            for register in extract_address_registers(goal["address"], arch):
                desired.setdefault(register, normalize_value(scratch[min(goal_number, len(scratch) - 1)]))
        if isinstance(goal["value"], dict):
            continue
        goal_value = normalize_value(goal["value"])
        for gadget in index.memory_write.get(normalize_address(goal["address"]), []):
            for effect in gadget.semantics["memory_effects"]["writes"]:
                if normalize_address(effect["address"]) == normalize_address(goal["address"]) and effect["value"].get("kind") == "register":
                    seeds.setdefault(effect["value"]["value"], goal_value)
    return seeds


def extract_address_registers(address: str, arch: str) -> list[str]:
    """Extract canonical registers from a normalized address expression.

    Args:
        address: Extractor address, symbolic address, or emulator address being processed.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        Canonical registers referenced by the address expression.
    """
    return [
        registers.canonical_register(token, arch)
        for token in re.findall(r"\b[a-z][a-z0-9]*\b", address.lower())
        if registers.is_register(token, arch)
    ]


def evaluate(
    effect: dict[str, Any],
    values: dict[str, str],
    stack_value: str | None = None,
) -> str | None:
    """Evaluate a symbolic effect against known register and stack values.

    Args:
        effect: Symbolic operand or memory effect to evaluate.
        values: Known symbolic register or stack values.
        stack_value: Value assigned to an unresolved stack effect.

    Returns:
        Resolved normalized value, symbolic expression, or ``None`` for unknown effects.
    """
    kind = effect.get("kind")
    if kind == "stack":
        return stack_value
    if kind in {"constant", "symbol"}:
        return normalize_value(effect["value"])
    if kind == "register":
        return values.get(effect["value"])
    if kind == "expression":
        arguments = [evaluate(argument, values) for argument in effect["args"]]
        return evaluate_expression(effect["op"], arguments)
    return None


def evaluate_expression(operator: str, arguments: list[str | None]) -> str | None:
    """Evaluate a supported integer expression or retain it symbolically.

    Args:
        operator: Symbolic arithmetic or assignment operator.
        arguments: Symbolic expression arguments to evaluate.

    Returns:
        Resolved integer, retained symbolic expression, or ``None`` for invalid arguments.
    """
    if not arguments or any(argument is None for argument in arguments):
        return None
    try:
        numbers = [int(argument, 0) for argument in arguments]
    except (TypeError, ValueError):
        return f"{operator}({','.join(str(argument) for argument in arguments)})"
    if operator in {"inc", "dec", "neg", "not", "bswap"}:
        value = {"inc": numbers[0] + 1, "dec": numbers[0] - 1, "neg": -numbers[0], "not": ~numbers[0]} .get(operator)
        if operator == "bswap":
            width = max(1, (numbers[0].bit_length() + 7) // 8)
            value = int.from_bytes(numbers[0].to_bytes(width, "little"), "big")
    elif len(numbers) < 2:
        return None
    else:
        value = {
            "add": numbers[0] + numbers[1], "sub": numbers[0] - numbers[1],
            "xor": numbers[0] ^ numbers[1], "and": numbers[0] & numbers[1],
            "or": numbers[0] | numbers[1], "shl": numbers[0] << numbers[1],
            "sal": numbers[0] << numbers[1], "shr": numbers[0] >> numbers[1],
        }.get(operator)
    return None if value is None else f"0x{value:x}"


def memory_matches(
    effect: dict[str, Any],
    goal: dict[str, Any],
    values: dict[str, str],
    arch: str,
) -> bool:
    """Return whether a modeled memory effect satisfies one write goal.

    Args:
        effect: Symbolic operand or memory effect to evaluate.
        goal: Memory-write goal being tested.
        values: Known symbolic register or stack values.
        arch: Target architecture, either ``x86`` or ``x64``.

    Returns:
        True when a modeled memory effect satisfies one write goal; otherwise ``False``.
    """
    if normalize_address(effect["address"]) != normalize_address(goal["address"]):
        return False
    if goal.get("width") and effect.get("width") != goal["width"]:
        return False
    expected = goal["value"]
    actual = effect["value"]
    if isinstance(expected, dict) and set(expected) == {"register"}:
        return actual.get("kind") == "register" and actual.get("value") == registers.canonical_register(expected["register"], arch)
    expected = normalize_value(expected)
    actual_value = evaluate(actual, values)
    return actual_value == expected


def transition_matches(gadget: Gadget, transition: dict[str, Any]) -> bool:
    """Return whether a gadget reaches the requested control target.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        transition: Required final control-flow transition.

    Returns:
        True when a gadget reaches the requested control target; otherwise ``False``.
    """
    for effect in gadget.semantics["control_effects"]:
        if effect["kind"] != transition["kind"]:
            continue
        expected = transition.get("target")
        if expected is None:
            return True
        target = effect.get("target", {})
        if isinstance(expected, dict) and set(expected) == {"register"}:
            return target.get("kind") == "register" and target.get("value") == registers.canonical_register(expected["register"], gadget.arch)
        if isinstance(expected, str):
            return target.get("value") == expected.lower()
    return False


def complete(
    state: SearchState,
    desired: dict[str, str],
    memory_goals: list[dict[str, Any]],
    transition: dict[str, Any] | None,
) -> bool:
    """Return whether every synthesis postcondition is satisfied.

    Args:
        state: Immutable synthesis state before the operation.
        desired: Required final register values.
        memory_goals: Required symbolic memory writes.
        transition: Required final control-flow transition.

    Returns:
        True when every synthesis postcondition is satisfied; otherwise ``False``.
    """
    values = dict(state.values)
    return (
        all(values.get(register) == value for register, value in desired.items())
        and len(state.memory_goals) == len(memory_goals)
        and (not transition or state.control_done)
    )


def satisfaction(
    state: SearchState,
    desired: dict[str, str],
    memory_goals: list[dict[str, Any]],
    transition: dict[str, Any] | None,
) -> int:
    """Count synthesis postconditions already satisfied by a state.

    Args:
        state: Immutable synthesis state before the operation.
        desired: Required final register values.
        memory_goals: Required symbolic memory writes.
        transition: Required final control-flow transition.

    Returns:
        Number of register, memory, and transition goals currently met.
    """
    values = dict(state.values)
    return (
        sum(values.get(register) == value for register, value in desired.items())
        + len(state.memory_goals)
        + int(bool(transition) and state.control_done)
    )


def heuristic(
    state: SearchState,
    desired: dict[str, str],
    memory_goals: list[dict[str, Any]],
    transition: dict[str, Any] | None,
) -> int:
    """Estimate the remaining search cost from unsatisfied goals.

    Args:
        state: Immutable synthesis state before the operation.
        desired: Required final register values.
        memory_goals: Required symbolic memory writes.
        transition: Required final control-flow transition.

    Returns:
        Admissible count of goals that remain unsatisfied.
    """
    maximum = len(desired) + len(memory_goals) + int(bool(transition))
    return (maximum - satisfaction(state, desired, memory_goals, transition)) * 20


def state_key(
    state: SearchState,
) -> tuple[tuple[tuple[str, str], ...], tuple[int, ...], bool, str | None]:
    """Return the semantic identity used to deduplicate search states.

    Args:
        state: Immutable synthesis state before the operation.

    Returns:
        Register, completed-memory, control, and architecture identity.
    """
    return state.values, state.memory_goals, state.control_done, state.arch


def context_cost(
    gadget: Gadget,
    constraints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score gadget side effects in the supplied exploit context.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        constraints: Semantic filters and context-sensitive ranking constraints.

    Returns:
        Total context-sensitive score and weighted side-effect components.
    """
    constraints = constraints or {}
    semantics = gadget.semantics
    desired_reads = set(constraints.get("require_reads", []))
    desired_writes = set(constraints.get("require_writes", []))
    live_values = set(constraints.get("live_values", {}))
    components = {
        "instructions": len(gadget.instructions),
        "extra_clobbers": len(set(semantics["clobbers"]) - desired_writes) * 8,
        "live_clobbers": len(set(semantics["clobbers"]) & live_values) * 24,
        "extra_reads": len(set(semantics["register_reads"]) - desired_reads) * 2,
        "stack": abs(semantics["stack_delta"]) // (8 if gadget.arch == "x64" else 4) if semantics["stack_delta"] is not None else 100,
        "memory": (len(semantics["memory_reads"]) + len(semantics["memory_writes"])) * 8,
        "unknown": len(semantics["unknown"]) * 100,
    }
    return {"score": sum(components.values()), "components": components}


def context_sort_key(
    gadget: Gadget,
    constraints: dict[str, Any] | None = None,
) -> tuple[int, str, str, int, str]:
    """Return a deterministic context-sensitive gadget ordering key.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        constraints: Semantic filters and context-sensitive ranking constraints.

    Returns:
        Context cost, provenance, address, and instruction ordering fields.
    """
    cost = context_cost(gadget, constraints)
    return cost["score"], gadget.module or "", gadget.source_id or "", int(gadget.address, 16), gadget.raw


def build_chain(state: SearchState, specification: dict[str, Any]) -> dict[str, Any]:
    """Serialize a solved state into words, frames, and validation issues.

    Args:
        state: Immutable synthesis state before the operation.
        specification: Normalized chain synthesis specification.

    Returns:
        Resolved and symbolic chain words, per-step stack frames, renderings, and issues.
    """
    gadgets = list(state.gadgets)
    stack_inputs = [dict(inputs) for inputs in state.stack_inputs]
    call = specification.get("call")
    arch = state.arch or ("x64" if "x64" in specification["abi"] else "x86")
    word_size = 8 if arch == "x64" else 4
    words = []
    frames = []
    issues = []
    preconditions = []
    if gadgets:
        words.append(gadget_word(gadgets[0], specification["bases"]))

    for index, gadget in enumerate(gadgets):
        stack = gadget.semantics["stack"]
        frame = {"gadget_id": gadget.identifier, "word_offset": len(words) - 1, "slots": []}
        before = stack["before_return"]
        if before is None or before < 0 or before % word_size:
            issues.append(f"gadget {gadget.identifier}: stack frame is not serializable")
            frames.append(frame)
            continue
        slots = {slot["offset"]: slot for slot in stack["slots"]}
        for offset in range(0, before, word_size):
            slot = slots.get(offset)
            value = stack_inputs[index].get(slot["register"]) if slot else None
            word = value_word(value, "pop" if value is not None else "padding")
            words.append(word)
            frame["slots"].append({"offset": offset, **word})
        if gadget.semantics["terminator"] in {"ret", "retn"}:
            if index + 1 < len(gadgets):
                continuation = gadget_word(gadgets[index + 1], specification["bases"])
            elif call:
                continuation = target_word(call, specification["bases"])
            else:
                continuation = value_word(specification["filler"], "continuation")
            words.append(continuation)
            frame["continuation"] = continuation
            adjustment = stack["return_adjust"] or 0
            for _ in range(0, adjustment, word_size):
                words.append(value_word(specification["filler"], "padding"))
        frames.append(frame)

    if call:
        if not gadgets:
            words.append(target_word(call, specification["bases"]))
        words.extend(call_frame(call, specification, word_size))
    transition = specification.get("transition")
    if transition and transition["kind"] in {"iret", "iretd", "iretq"}:
        frame = transition.get("frame")
        if frame:
            words.extend(value_word(frame[field], f"iret_{field}") for field in ("ip", "cs", "flags", "sp", "ss"))
        else:
            preconditions.append("supply a five-word iret privilege-transition frame")

    if specification["abi"] in {"windows-x64", "windows-x64-kernel", "sysv-x64"}:
        preconditions.append("target entry rsp must be 8 modulo 16")
    if "cfg" in specification["mitigations"] and transition and transition["kind"] in {"call", "jmp"}:
        preconditions.append("indirect control target must be CFG-valid")
    if "kpti" in specification["mitigations"] and transition and transition["kind"] in {"iret", "iretd", "iretq", "sysret"}:
        preconditions.append("kernel-to-user transition must restore the user page table or use the KPTI trampoline")
    if "smep" in specification["mitigations"] and specification["abi"] == "windows-x64-kernel":
        preconditions.append("kernel control targets must be supervisor executable")
    if "smap" in specification["mitigations"] and specification["abi"] == "windows-x64-kernel" and specification["write"]:
        preconditions.append("kernel memory operands must not require disallowed user-page access")
    if "cet" in specification["mitigations"] and (call or any(gadget.semantics["terminator"] in {"ret", "retn"} for gadget in gadgets)):
        issues.append("CET shadow stack prevents the selected return chain")

    bad_words = find_bad_words(words, word_size, specification["bad_bytes"])
    if bad_words:
        issues.append(f"bad bytes in resolved chain words: {','.join(str(index) for index in bad_words)}")
    unresolved = [index for index, word in enumerate(words) if not word.get("resolved", False)]
    if unresolved:
        preconditions.append(f"resolve symbolic chain words before byte validation: {','.join(str(index) for index in unresolved)}")
    if len(words) > specification["max_words"]:
        issues.append(f"chain uses {len(words)} words, maximum is {specification['max_words']}")
    return {
        "abi": specification["abi"],
        "word_size": word_size,
        "word_count": len(words),
        "words": words,
        "frames": frames,
        "bad_byte_words": bad_words,
        "unresolved_words": unresolved,
        "issues": issues,
        "preconditions": preconditions,
        "target_clobbers": list(ABI_CLOBBERS[specification["abi"]]) if call else [],
    }


def gadget_word(gadget: Gadget, bases: dict[str, Any]) -> dict[str, Any]:
    """Describe a gadget address as a chain word.

    Args:
        gadget: Gadget to inspect, rank, format, or apply.
        bases: Known module base addresses used to resolve relative addresses.

    Returns:
        Serialized gadget address word.
    """
    return address_word("gadget", gadget.module, gadget.address, gadget.address_kind, bases, gadget.identifier)


def target_word(target: dict[str, Any], bases: dict[str, Any]) -> dict[str, Any]:
    """Describe a direct or symbolic transfer target as a chain word.

    Args:
        target: Direct or symbolic control-transfer target.
        bases: Known module base addresses used to resolve relative addresses.

    Returns:
        Serialized control-transfer target word.
    """
    if "symbol" in target:
        return {"kind": "target", "value": target["symbol"], "resolved": False}
    return address_word("target", target.get("module"), target["address"], target.get("address_kind", "rva"), bases)


def address_word(
    kind: str,
    module: str | None,
    address: str,
    address_kind: str,
    bases: dict[str, Any],
    gadget_id: str | None = None,
) -> dict[str, Any]:
    """Resolve or relocate an address-bearing chain word.

    Args:
        kind: Chain-word or address category.
        module: Source module name.
        address: Extractor address, symbolic address, or emulator address being processed.
        address_kind: Interpretation of addresses as unknown, relative, or virtual.
        bases: Known module base addresses used to resolve relative addresses.
        gadget_id: Stable gadget identifier to include in the record.

    Returns:
        Address word with relocation and resolution metadata.
    """
    result = {"kind": kind, "module": module, "address": address, "address_kind": address_kind}
    if gadget_id:
        result["gadget_id"] = gadget_id
    parsed_address = int(address, 0)
    if address_kind == "va":
        result.update(value=f"0x{parsed_address:x}", resolved=True)
    elif address_kind == "rva" and module in bases:
        base = normalize_value(bases[module])
        try:
            result.update(value=f"0x{int(base, 0) + parsed_address:x}", resolved=True)
        except (TypeError, ValueError):
            result.update(value=f"{base}+0x{parsed_address:x}", resolved=False)
    else:
        result.update(value=f"{module or '<module>'}+0x{parsed_address:x}", resolved=False)
    return result


def value_word(value: Any, kind: str = "value") -> dict[str, Any]:
    """Normalize a literal or symbolic value into a chain word.

    Args:
        value: Input value to parse, validate, or normalize.
        kind: Chain-word or address category.

    Returns:
        Normalized literal or symbolic value word.
    """
    normalized = normalize_value(value) if value is not None else "<filler>"
    try:
        parsed = int(normalized, 0)
    except (TypeError, ValueError):
        return {"kind": kind, "value": normalized, "resolved": False}
    return {"kind": kind, "value": f"0x{parsed:x}", "resolved": True}


def call_frame(
    call: dict[str, Any], specification: dict[str, Any], word_size: int
) -> list[dict[str, Any]]:
    """Build ABI-specific return, shadow-space, and argument words.

    Args:
        call: ABI call goal to serialize.
        specification: Normalized chain synthesis specification.
        word_size: Target pointer width in bytes.

    Returns:
        Architecture ABI argument, shadow-space, and return words.
    """
    words = [value_word(call.get("return", specification["filler"]), "return")]
    if specification["abi"] in {"windows-x64", "windows-x64-kernel"}:
        words.extend(value_word(specification["filler"], "shadow") for _ in range(4))
        arguments = call.get("arguments", [])[4:]
    elif specification["abi"] == "x86-cdecl":
        arguments = call.get("arguments", [])
    elif specification["abi"] == "sysv-x64":
        arguments = call.get("arguments", [])[6:]
    else:
        arguments = []
    words.extend(value_word(argument, "argument") for argument in arguments)
    return words


def find_bad_words(
    words: list[dict[str, Any]], word_size: int, bad_bytes: list[str]
) -> list[int]:
    """Return resolved chain-word indexes containing forbidden bytes.

    Args:
        words: Serialized chain words to inspect.
        word_size: Target pointer width in bytes.
        bad_bytes: Forbidden byte values represented as two-digit hexadecimal strings.

    Returns:
        Indexes of resolved words containing a forbidden byte.
    """
    if not bad_bytes:
        return []
    forbidden = {int(value, 16) for value in bad_bytes}
    results = []
    for index, word in enumerate(words):
        if not word.get("resolved"):
            continue
        value = int(word["value"], 0) & ((1 << (word_size * 8)) - 1)
        if forbidden & set(value.to_bytes(word_size, "little")):
            results.append(index)
    return results


def render_chain(chain: dict[str, Any]) -> dict[str, str]:
    """Render a serialized chain as Python and pwntools source.

    Args:
        chain: Serialized chain containing gadget and stack words.

    Returns:
        Equivalent Python and pwntools chain source.
    """
    expressions = [word_expression(word) for word in chain["words"]]
    pack = "<Q" if chain["word_size"] == 8 else "<L"
    python = ["from struct import pack", "rop = b\"\""]
    for expression in expressions:
        python.append(f"rop += pack(\"{pack}\", {expression})")
    pwntools = ["from pwn import flat", "chain = ["]
    pwntools.extend(f"    {expression}," for expression in expressions)
    pwntools.extend(["]", f"rop = flat(chain, word_size={chain['word_size'] * 8}, endianness=\"little\")"])
    return {"python": "\n".join(python), "pwntools": "\n".join(pwntools)}


def word_expression(word: dict[str, Any]) -> str:
    """Return a source-code expression for one serialized chain word.

    Args:
        word: Serialized chain word.

    Returns:
        Source-code expression preserving resolution and relocation.
    """
    if word.get("resolved"):
        return word["value"]
    if word.get("address_kind") == "rva":
        module = re.sub(r"\W+", "_", word.get("module") or "module").strip("_").lower()
        return f"base_{module}+{word['address']}"
    value = re.sub(r"\W+", "_", str(word["value"])).strip("_").lower()
    return value or "value"


def normalize_value(value: Any) -> str:
    """Normalize a literal or symbolic exploit value to text.

    Args:
        value: Input value to parse, validate, or normalize.

    Returns:
        Canonical integer literal or stripped symbolic value.
    """
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return f"0x{value:x}"
    return str(value).strip()


def normalize_address(value: str) -> str:
    """Normalize a memory address expression for semantic comparison.

    Args:
        value: Input value to parse, validate, or normalize.

    Returns:
        Whitespace-free bracketed address expression.
    """
    value = re.sub(r"^(?:byte|word|dword|qword)\s+(?:ptr\s+)?", "", value.lower()).strip()
    return re.sub(r"\s+", "", value)
