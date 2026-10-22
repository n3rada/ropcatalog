# ropcatalog/core/utils.py

# Built-in imports
import re
from pathlib import Path

# Third-party imports
from chardet import UniversalDetector


def detect_arch_from_text(content: str) -> str:
    """Detect x86 or x64 architecture from gadget extractor output.

    Args:
        content: Gadget extractor output to inspect.

    Returns:
        Detected ``x86`` or ``x64`` architecture.
    """
    for line in content.splitlines():
        line = line.strip().lower()
        if line.startswith("fileformat:") and "arch:" in line:
            if re.search(r"\b(?:x64|x86[-_]64|amd64)\b", line):
                return "x64"
            if "x86" in line:
                return "x86"

    address = re.search(r"^\s*0x([0-9a-fA-F]+)\s*:", content, re.MULTILINE)
    if address and len(address.group(1)) > 8:
        return "x64"
    if re.search(r"\b(?:r(?:ax|bx|cx|dx|si|di|bp|sp|ip)|r(?:[89]|1[0-5])(?:d|w|b)?)\b", content):
        return "x64"
    return "x86"


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
    with open(file_path, mode="rb") as stream:
        prefix = stream.read(4096)
    if b"\x00" not in prefix:
        try:
            prefix.decode("utf-8-sig")
            print(f"[+] Detected encoding for '{file_path.name}': utf-8")
            return "utf-8-sig" if prefix.startswith(b"\xef\xbb\xbf") else "utf-8"
        except UnicodeDecodeError:
            pass

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
            return detect_arch_from_text(f.read())
    except UnicodeDecodeError:
        print(f"[!] Failed to decode '{file_path.name}' with encoding '{encoding}'.")
        print("[!] Try specifying a different encoding with --encoding.")
        raise SystemExit(1)


def format_bad_chars(bad_chars_string: str) -> list[str]:
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
