# tests/test_cli.py

"""Tests for the CLI argument parser."""

import pytest
from ropcatalog.cli import build_parser


class TestBuildParser:
    @pytest.fixture
    def parser(self):
        return build_parser()

    def test_single_path(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.paths == ["gadgets.txt"]

    def test_multiple_paths(self, parser):
        args = parser.parse_args(["file1.txt", "file2.txt", "file3.txt"])
        assert args.paths == ["file1.txt", "file2.txt", "file3.txt"]

    def test_bad_characters_short(self, parser):
        args = parser.parse_args(["gadgets.txt", "-b", r"\x00\x0a"])
        assert args.bad_characters == r"\x00\x0a"

    def test_bad_characters_long(self, parser):
        args = parser.parse_args(["gadgets.txt", "--bad-characters", r"\x00"])
        assert args.bad_characters == r"\x00"

    def test_bad_characters_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.bad_characters == ""

    def test_all_flag(self, parser):
        args = parser.parse_args(["gadgets.txt", "-a"])
        assert args.all is True

    def test_all_flag_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.all is False

    def test_style_choices(self, parser):
        for style in ("plain", "python", "js", "cpp"):
            args = parser.parse_args(["gadgets.txt", "-s", style])
            assert args.style == style

    def test_style_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.style == "plain"

    def test_style_invalid(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["gadgets.txt", "-s", "invalid"])

    def test_offset_flag(self, parser):
        args = parser.parse_args(["gadgets.txt", "-o"])
        assert args.offset is True

    def test_offset_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.offset is False

    def test_encoding(self, parser):
        args = parser.parse_args(["gadgets.txt", "-e", "utf-16"])
        assert args.encoding == "utf-16"

    def test_encoding_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.encoding is None

    def test_command(self, parser):
        args = parser.parse_args(["gadgets.txt", "-c", "pivot reg"])
        assert args.command == "pivot reg"

    def test_command_default(self, parser):
        args = parser.parse_args(["gadgets.txt"])
        assert args.command is None

    def test_combined_args(self, parser):
        args = parser.parse_args([
            "gadgets.txt", "other.txt",
            "-b", r"\x00\x0a",
            "-a",
            "-s", "python",
            "-o",
            "-e", "utf-8",
            "-c", "copy eax",
        ])
        assert args.paths == ["gadgets.txt", "other.txt"]
        assert args.bad_characters == r"\x00\x0a"
        assert args.all is True
        assert args.style == "python"
        assert args.offset is True
        assert args.encoding == "utf-8"
        assert args.command == "copy eax"

    def test_no_paths_fails(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args([])
