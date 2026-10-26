"""Streaming JSONL request server."""

# Built-in imports
import io
import sys

# Local library imports
from ..application.requests import _parse_batch_line
from ..application.workflows import execute_queries
from . import formatters
from . import terminal
from .output import write_jsonl

def serve_requests(
    console: terminal.Terminal,
    formatter: formatters.GadgetFormatter,
    with_base_address: bool,
    limit: int | None,
    fields: tuple[str, ...] | None,
) -> int:
    """Serve JSONL requests against a catalog kept in memory.

    Args:
        console: Terminal instance bound to the loaded gadget catalog.
        formatter: Formatter used to render gadgets in output records.
        with_base_address: Whether formatted addresses use module base expressions.
        limit: Maximum number of gadgets to emit per request.
        fields: Optional JSONL gadget fields to retain.

    Returns:
        Zero after standard input reaches end-of-file.
    """
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


