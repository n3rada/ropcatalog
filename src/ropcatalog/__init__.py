# Built-in imports
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
import re

try:
    __version__ = version("ropcatalog")
except PackageNotFoundError:
    # Fallback: read directly from pyproject.toml for development
    try:
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        version_match = re.search(
            r'^version\s*=\s*"([^"]+)"\s*$',
            pyproject_path.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        __version__ = f"{version_match.group(1)}-dev" if version_match else "unknown"
    except FileNotFoundError:
        __version__ = "unknown"

__all__ = ["__version__"]
