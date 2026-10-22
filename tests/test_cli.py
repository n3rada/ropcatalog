# tests/test_cli.py

"""Tests for the CLI argument parser."""

import json
import sys

import pytest
from ropcatalog.cli import build_parser, main, parse_batch_queries


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

    def test_repeatable_queries(self, parser):
        args = parser.parse_args(["gadgets.txt", "-q", "pop rdi", "-q", "pivot reg"])
        assert args.query == ["pop rdi", "pivot reg"]

    def test_batch_and_jsonl(self, parser):
        args = parser.parse_args(["gadgets.txt", "--batch", "queries.txt", "--jsonl"])
        assert args.batch == "queries.txt"
        assert args.jsonl is True

    def test_artifact_dir(self, parser, tmp_path):
        args = parser.parse_args(["gadgets.txt", "-q", "pop rdi", "--jsonl", "--artifact-dir", str(tmp_path)])
        assert args.artifact_dir == tmp_path

    @pytest.mark.parametrize("query_modes", [
        ["-c", "pivot reg", "-q", "pop rdi ; ret"],
        ["-c", "pivot reg", "--batch", "queries.jsonl"],
        ["-q", "pop rdi ; ret", "--batch", "queries.jsonl"],
    ])
    def test_query_modes_are_mutually_exclusive(self, parser, query_modes):
        with pytest.raises(SystemExit):
            parser.parse_args(["gadgets.txt", *query_modes])

    @pytest.mark.parametrize("arguments", [
        ["--jsonl"],
        ["--limit", "1"],
        ["--artifact-dir", "artifacts"],
        ["--batch", "queries.jsonl", "--artifact-dir", "artifacts"],
    ])
    def test_output_modes_require_dependencies(self, parser, arguments):
        with pytest.raises(SystemExit):
            parser.parse_args(["gadgets.txt", *arguments])

    @pytest.mark.parametrize("limit", ["0", "-1"])
    def test_limit_must_be_positive(self, parser, limit):
        with pytest.raises(SystemExit):
            parser.parse_args(["gadgets.txt", "-q", "pop rdi ; ret", "--limit", limit])

    @pytest.mark.parametrize("query_mode", ["-c", "-q", "--batch"])
    def test_query_mode_value_must_not_be_empty(self, parser, query_mode):
        with pytest.raises(SystemExit):
            parser.parse_args(["gadgets.txt", query_mode, ""])

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


class TestBatchMode:
    def test_parses_raw_and_semantic_queries(self, tmp_path):
        batch = tmp_path / "queries.jsonl"
        batch.write_text(
            "# ignored\n\npop rdi ; ret\n"
            '{"id":"pivot","command":"pivot reg"}\n',
            encoding="utf-8",
        )

        queries = parse_batch_queries(str(batch))

        assert [(query.identifier, query.command) for query in queries] == [
            ("3", "pop rdi ; ret"),
            ("pivot", "pivot reg"),
        ]
        assert [query.raw_gadget for query in queries] == [True, False]

    def test_json_query_requires_one_mode(self, tmp_path):
        batch = tmp_path / "queries.jsonl"
        batch.write_text('{"query":"ret","command":"pivot rsp"}\n', encoding="utf-8")

        with pytest.raises(ValueError, match="exactly one"):
            parse_batch_queries(str(batch))

    def test_jsonl_module_artifact_suppresses_stdout(self, tmp_path, monkeypatch, capsys):
        catalog = tmp_path / "libphp.so.txt"
        catalog.write_text(
            "FileFormat: ELF, Arch: x64\n"
            "0x194fc5: pop rdi ; ret\n"
            "0x123456: pop rdi ; pop rbp ; ret\n",
            encoding="utf-8",
        )
        artifacts = tmp_path / "artifacts"
        monkeypatch.setattr(sys, "argv", [
            "ropcatalog",
            str(catalog),
            "-q", "pop rdi ; ret",
            "-q", "? pop rdi ; ret",
            "--jsonl",
            "--limit", "1",
            "--artifact-dir", str(artifacts),
        ])

        assert main() == 0

        captured = capsys.readouterr()
        assert captured.out == ""

        artifact = artifacts / "libphp.so.ropcatalog.jsonl"
        assert captured.err == f"[+] Wrote 2 query result(s): {artifact}\n"
        assert artifact.is_file()
        artifact_records = [json.loads(line) for line in artifact.read_text().splitlines()]
        assert artifact_records[0]["schema"] == "ropcatalog.query.v1"
        assert artifact_records[0]["count"] == 1
        assert artifact_records[0]["total"] == 1
        assert artifact_records[0]["gadgets"][0]["module"] == "libphp.so"
        assert artifact_records[0]["gadgets"][0]["arch"] == "x64"
        assert artifact_records[1]["query"] == "? pop rdi ; ret"
