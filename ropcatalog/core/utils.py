# Built-in imports
import re
from pathlib import Path


def detect_arch_from_file(file_path: Path) -> str:
    """
    Detects the architecture ('x86' or 'x64') from the rp++ dump file.

    Args:
        file_path (Path): Path to the rp++ gadget dump file.

    Returns:
        str: 'x86' or 'x64'. Defaults to 'x86' if not found.
    """
    with open(file_path, mode="r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("FileFormat:") and "Arch:" in line:
                if "x64" in line:
                    return "x64"
                elif "x86" in line:
                    return "x86"
    return "x86"  # default fallback


def format_bad_chars(bad_chars_string: str) -> list:
    """
    Formats a string of bad characters (e.g. '\\x00\\x0a') into a list of hex strings in lowercase.

    Args:
        bad_chars_string (str): String of bad characters in the form '\\x00\\x0a'.

    Returns:
        list: A list of lowercase bad character hex strings, e.g., ['00', '0a'].
    """

    # Use regex to find all hex characters after \\x and convert to lowercase
    return [
        match.lower() for match in re.findall(r"\\x([0-9a-fA-F]{2})", bad_chars_string)
    ]
