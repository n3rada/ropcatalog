# tests/test_utils.py

"""Tests for utility functions."""

import pytest
from pathlib import Path
from ropcatalog.core.utils import format_bad_chars, detect_arch_from_file, detect_file_encoding


class TestFormatBadChars:
    def test_standard_format(self):
        result = format_bad_chars(r"\x00\x0a\x0d")
        assert result == ["00", "0a", "0d"]

    def test_uppercase_input(self):
        result = format_bad_chars(r"\x0A\x0D")
        assert result == ["0a", "0d"]

    def test_single_char(self):
        result = format_bad_chars(r"\x00")
        assert result == ["00"]

    def test_empty_string(self):
        result = format_bad_chars("")
        assert result == []

    def test_no_valid_hex(self):
        result = format_bad_chars("not hex at all")
        assert result == []

    def test_mixed_content(self):
        result = format_bad_chars(r"junk\x0amore\x0djunk")
        assert result == ["0a", "0d"]


class TestDetectArchFromFile:
    def test_x64_detected(self, tmp_path):
        f = tmp_path / "gadgets_x64.txt"
        f.write_text("FileFormat: PE | Arch: x64\n0x1000: pop rax ; ret (1 found)\n", encoding="utf-8")
        assert detect_arch_from_file(f, encoding="utf-8") == "x64"

    def test_x86_detected(self, tmp_path):
        f = tmp_path / "gadgets_x86.txt"
        f.write_text("FileFormat: PE | Arch: x86\n0x1000: pop eax ; ret (1 found)\n", encoding="utf-8")
        assert detect_arch_from_file(f, encoding="utf-8") == "x86"

    def test_default_x86_when_missing(self, tmp_path):
        f = tmp_path / "gadgets_noarch.txt"
        f.write_text("0x1000: pop eax ; ret (1 found)\n", encoding="utf-8")
        assert detect_arch_from_file(f, encoding="utf-8") == "x86"

    def test_autodetect_encoding(self, tmp_path):
        f = tmp_path / "gadgets.txt"
        f.write_text("FileFormat: PE | Arch: x64\n0x1000: pop rax ; ret (1 found)\n", encoding="utf-8")
        assert detect_arch_from_file(f) == "x64"


class TestDetectFileEncoding:
    def test_utf8(self, tmp_path):
        f = tmp_path / "utf8.txt"
        f.write_text("Hello, world!\n", encoding="utf-8")
        encoding = detect_file_encoding(f)
        assert encoding.lower().replace("-", "") in ("utf8", "ascii")

    def test_utf16(self, tmp_path):
        f = tmp_path / "utf16.txt"
        f.write_text("Hello, world!\n", encoding="utf-16")
        encoding = detect_file_encoding(f)
        assert "16" in encoding.lower() or "utf" in encoding.lower()
