import ast
from pathlib import Path
import re


SOURCE_ROOT = Path(__file__).parents[1] / "src" / "ropcatalog"


def test_production_callables_have_complete_docstrings_and_types():
    failures = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path), feature_version=(3, 10))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            docstring = ast.get_docstring(node) or ""
            if not docstring or "_description_" in docstring:
                failures.append(f"{path}:{node.lineno} missing docstring")
            arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            documented_arguments = [
                argument
                for argument in arguments
                if argument.arg not in {"self", "cls"}
            ]
            if any(argument.annotation is None for argument in documented_arguments):
                failures.append(f"{path}:{node.lineno} missing argument annotation")
            if documented_arguments:
                if "Args:" not in docstring:
                    failures.append(f"{path}:{node.lineno} missing Args section")
                for argument in documented_arguments:
                    if not re.search(
                        rf"^\s*{re.escape(argument.arg)}(?:\s*\([^\n:]+\))?:",
                        docstring,
                        re.MULTILINE,
                    ):
                        failures.append(
                            f"{path}:{node.lineno} missing documentation for {argument.arg}"
                        )
            if node.returns is None:
                failures.append(f"{path}:{node.lineno} missing return annotation")
            elif not (
                isinstance(node.returns, ast.Constant) and node.returns.value is None
            ) and "Returns:" not in docstring:
                failures.append(f"{path}:{node.lineno} missing Returns section")
            if node.args.vararg and node.args.vararg.annotation is None:
                failures.append(f"{path}:{node.lineno} missing vararg annotation")
            if node.args.kwarg and node.args.kwarg.annotation is None:
                failures.append(f"{path}:{node.lineno} missing kwarg annotation")

    assert failures == []
