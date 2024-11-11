# Built-in imports
import re


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
