# Built-in imports
import argparse
from collections.abc import Iterable
import io
import json
from pathlib import Path
import sys

# Local library imports
from .core import gadgets
from .core import utils
from .application.requests import Query, parse_batch_queries
from .application.workflows import execute_queries
from .interface import formatters
from .interface import terminal
from .interface.output import interface_contract, write_jsonl, write_module_artifacts
from .interface.serve import serve_requests


def parse_arguments(args: Iterable[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments using ``argparse``.

    Args:
        args: Arguments to parse, or ``None`` to read ``sys.argv``.

    Returns:
        Validated command-line namespace.

    Raises:
        SystemExit: If arguments violate an input or output contract.
    """
    parser = build_parser()
    parsed = parser.parse_args(args)
    return validate_arguments(parser, parsed, args is None)


def validate_arguments(
    parser: argparse.ArgumentParser,
    parsed: argparse.Namespace,
    from_process_args: bool,
) -> argparse.Namespace:
    """Reject combinations that cannot be expressed with argparse groups.

    Args:
        parser: Parser used to report a standard command-line error.
        parsed: Namespace produced by ``argparse``.
        from_process_args: Whether arguments came from the current process.

    Returns:
        Validated namespace, including implicit piped standard input.

    Raises:
        SystemExit: If arguments violate an input or output contract.
    """
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
            parser.error("--capabilities must be used alone")
        return parsed
    job_requested = noninteractive or parsed.catalog_out is not None
    if not parsed.paths:
        if from_process_args and job_requested and not parsed.serve and not sys.stdin.isatty():
            parsed.paths = ["-"]
        else:
            parser.error("provide an input path or pipe gadget output on standard input")
    if parsed.jsonl and not noninteractive:
        parser.error("--jsonl requires --command, --query, --batch, or --serve")
    if parsed.artifact_dir and not parsed.jsonl:
        parser.error("--artifact-dir requires --jsonl")
    if parsed.serve and parsed.artifact_dir:
        parser.error("--serve cannot be combined with --artifact-dir")
    if parsed.artifact_dir and parsed.verbose:
        parser.error("--verbose cannot be combined with --artifact-dir")
    if parsed.fields and not (parsed.jsonl or parsed.serve):
        parser.error("--fields requires --jsonl or --serve")
    if parsed.catalog_out and (
        noninteractive or parsed.jsonl or parsed.artifact_dir or parsed.limit is not None
        or parsed.fields or parsed.all or parsed.offset or parsed.style != "plain"
        or parsed.verbose
    ):
        parser.error("--catalog-out cannot be combined with query or JSONL output options")
    if parsed.limit is not None and not noninteractive:
        parser.error("--limit requires --command, --query, --batch, or --serve")
    if parsed.paths.count("-") > 1:
        parser.error("standard input may only be specified once")
    if "-" in parsed.paths and not job_requested:
        parser.error("standard input requires a non-interactive query or --catalog-out")
    if "-" in parsed.paths and parsed.batch == "-":
        parser.error("standard input cannot provide both gadgets and batch queries")
    if "-" in parsed.paths and parsed.serve:
        parser.error("standard input cannot provide both gadgets and served requests")
    if parsed.stdin_module and "-" not in parsed.paths:
        parser.error("--stdin-module requires a standard-input gadget source")
    if parsed.offset and parsed.address_kind == "va":
        parser.error("--offset cannot rebase addresses marked as virtual addresses")
    if parsed.artifact_dir and parsed.fields and "module" not in parsed.fields:
        parser.error("--artifact-dir requires the 'module' JSONL field")
    return parsed


def positive_integer(value: str) -> int:
    """Parse an integer greater than zero for ``argparse``.

    Args:
        value: Input value to parse, validate, or normalize.

    Returns:
        Parsed positive integer.

    Raises:
        ValueError: If the value is not a decimal integer.
        argparse.ArgumentTypeError: If the parsed integer is not greater than zero.
    """
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def output_fields(value: str) -> tuple[str, ...]:
    """Parse and validate a comma-delimited JSONL field selection.

    Args:
        value: Input value to parse, validate, or normalize.

    Returns:
        Deduplicated field names in user-specified order.

    Raises:
        argparse.ArgumentTypeError: If no fields or unsupported fields are supplied.
    """
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
    """Reject empty or whitespace-only command-line strings.

    Args:
        value: Input value to parse, validate, or normalize.

    Returns:
        Original non-empty string.

    Raises:
        argparse.ArgumentTypeError: If the value is empty or only whitespace.
    """
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the complete command-line argument parser.

    Returns:
        Fully configured ``ropcatalog`` argument parser.
    """
    parser = argparse.ArgumentParser(
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



def main() -> int:
    """Run the CLI with clean interruption handling.

    Returns:
        Process exit status, including 130 for interrupted execution.
    """
    stdout = sys.stdout
    try:
        return _run()
    except KeyboardInterrupt:
        print("[!] Interrupted.", file=sys.stderr)
        return 130
    finally:
        sys.stdout = stdout


def _run() -> int:
    """Parse arguments and dispatch the requested interface mode.

    Returns:
        Zero for successful requests and one for failures or incomplete results.
    """

    args = parse_arguments()
    real_stdout = sys.stdout
    diagnostics_stream = sys.stderr

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
                modules = {gadget.module or "unknown" for gadget in catalog.gadgets}
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
        return 0 if all(record["status"] == "ok" for record in records) else 1

    return console.start()
