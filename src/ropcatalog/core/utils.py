# ropcatalog/core/utils.py

# Built-in imports
import re
from pathlib import Path

# Third-party imports
from chardet import UniversalDetector


def detect_file_encoding(file_path: Path) -> str:
    """
    Detects the encoding of a file using chardet's streaming detector.

    Feeds the file line-by-line and stops as soon as chardet is confident.

    Args:
        file_path (Path): Path to the file.

    Returns:
        str: The detected encoding name (e.g., 'utf-8', 'UTF-16').

    Raises:
        SystemExit: When encoding cannot be determined.
    """
    detector = UniversalDetector()
    with open(file_path, mode="rb") as f:
        for line in f:
            detector.feed(line)
            if detector.done:
                break
    result = detector.close()
    encoding = result.get("encoding")
    confidence = result.get("confidence", 0)

    if not encoding:
        print(f"[!] Could not detect encoding for '{file_path.name}'.")
        print("[!] Specify it manually with --encoding (e.g., --encoding utf-16).")
        raise SystemExit(1)

    print(f"[+] Detected encoding for '{file_path.name}': {encoding} (confidence: {confidence:.0%})")
    return encoding


def detect_arch_from_file(file_path: Path, encoding: str | None = None) -> str:
    """
    Detects the architecture ('x86' or 'x64') from the rp++ dump file.

    Args:
        file_path (Path): Path to the rp++ gadget dump file.
        encoding (str | None): File encoding. Auto-detected if None.

    Returns:
        str: 'x86' or 'x64'. Defaults to 'x86' if not found.
    """
    if not encoding:
        encoding = detect_file_encoding(file_path)
    try:
        with open(file_path, mode="r", encoding=encoding) as f:
            for line in f:
                if line.startswith("FileFormat:") and "Arch:" in line:
                    if "x64" in line:
                        return "x64"
                    elif "x86" in line:
                        return "x86"
    except UnicodeDecodeError:
        print(f"[!] Failed to decode '{file_path.name}' with encoding '{encoding}'.")
        print("[!] Try specifying a different encoding with --encoding.")
        raise SystemExit(1)
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
