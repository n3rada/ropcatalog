"""Machine-readable interface contracts and output transports."""

# Built-in imports
import json
from pathlib import Path
import re
from typing import Any, TextIO

# Local library imports
from ..core import synthesis
from . import terminal

def interface_contract() -> dict[str, Any]:
    """Return the machine-readable interface and schema capabilities.

    Returns:
        Machine-readable supported input, query, schema, and verification capabilities.
    """
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


def write_jsonl(records: list[dict[str, Any]], stream: TextIO) -> None:
    """Write canonical one-object-per-line JSON records.

    Args:
        records: Machine-readable result records.
        stream: Text stream receiving JSONL output.
    """
    for record in records:
        print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=stream)


def write_module_artifacts(records: list[dict[str, Any]], artifact_dir: Path, modules: set[str]) -> list[Path]:
    """Write query records to deterministic per-module artifact files.

    Args:
        records: Machine-readable result records.
        artifact_dir: Directory in which module-specific JSONL artifacts are written.
        modules: Modules represented in the output records.

    Returns:
        Artifact paths in deterministic module order.
    """
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


