# tests/test_terminal.py

"""Tests for Terminal command dispatch and execution logic."""

import pytest
from unittest.mock import MagicMock
from ropcatalog.core.gadgets import Gadget, Gadgets
from ropcatalog.core.terminal import Terminal, requires_arg
from ropcatalog.core.formatters import PlainFormatter


class FakeCatalog:
    """Minimal stand-in for Gadgets that supports iteration without parsing files."""

    def __init__(self, gadget_list):
        self._active_list = list(gadget_list)
        self._full_list = list(gadget_list)
        self._unique_mode = True

    def __iter__(self):
        return iter(self._active_list)

    def __len__(self):
        return len(self._active_list)

    def use_full_catalog(self, enabled):
        pass

    def set_uniqueness(self, enabled):
        self._unique_mode = enabled


def _make_terminal(gadgets_raw, arch="x86"):
    """Helper to build a Terminal with a list of (address, raw) tuples."""
    gadget_objects = [
        Gadget(address=addr, raw_string=raw, module="testmod", arch=arch)
        for addr, raw in gadgets_raw
    ]
    catalog = FakeCatalog(gadget_objects)
    return Terminal(full_catalog=catalog, formatter=PlainFormatter())


class TestDispatch:
    def test_unrecognized_command(self, capsys):
        term = _make_terminal([])
        result = term.execute("nonexistent_cmd")
        assert result == []
        assert "Unrecognized command" in capsys.readouterr().out

    def test_requires_arg_missing(self, capsys):
        term = _make_terminal([("0x1000", "pop eax ; ret")])
        result = term.execute("copy")
        assert result == []
        assert "requires an argument" in capsys.readouterr().out

    def test_exit_raises_systemexit(self):
        term = _make_terminal([])
        with pytest.raises(SystemExit):
            term.execute("exit")


class TestSearchCommands:
    @pytest.fixture
    def term(self):
        return _make_terminal(
            [
                ("0x1000", "pop eax ; ret"),
                ("0x1004", "pop ebx ; ret"),
                ("0x1008", "mov eax, ecx ; ret"),
                ("0x100c", "xor eax, eax ; ret"),
            ]
        )

    def test_exact_search(self, term):
        results = term.execute("? pop eax ; ret")
        assert len(results) == 1
        assert results[0].address == "0x1000"

    def test_exact_search_no_match(self, term):
        results = term.execute("? pop ecx ; ret")
        assert len(results) == 0

    def test_partial_search(self, term):
        results = term.execute("/ pop")
        assert len(results) == 2

    def test_regex_search(self, term):
        results = term.execute(". mov.*ecx")
        assert len(results) == 1
        assert results[0].address == "0x1008"


class TestRegisterCommands:
    @pytest.fixture
    def term(self):
        return _make_terminal(
            [
                ("0x1000", "mov ebx, eax ; ret"),
                ("0x1004", "mov eax, ecx ; ret"),
                ("0x1008", "xor eax, eax ; ret"),
                ("0x100c", "push esp ; pop eax ; ret"),
                ("0x1010", "xchg eax, ebx ; ret"),
                ("0x1014", "inc eax ; ret"),
                ("0x1018", "dec eax ; ret"),
                ("0x101c", "add eax, ecx ; ret"),
                ("0x1020", "sub eax, ecx ; ret"),
            ]
        )

    def test_copy_register(self, term):
        results = term.execute("copy eax")
        assert any("mov ebx, eax" in g.raw for g in results)

    def test_copy_to_register(self, term):
        results = term.execute("copyto eax")
        assert any("mov eax, ecx" in g.raw for g in results)

    def test_zero(self, term):
        results = term.execute("zero eax")
        assert any("xor eax, eax" in g.raw for g in results)

    def test_swap(self, term):
        results = term.execute("swap eax")
        assert any("xchg eax, ebx" in g.raw for g in results)

    def test_inc(self, term):
        results = term.execute("inc eax")
        assert any("inc eax" in g.raw for g in results)

    def test_dec(self, term):
        results = term.execute("dec eax")
        assert any("dec eax" in g.raw for g in results)


class TestMemoryCommands:
    @pytest.fixture
    def term(self):
        return _make_terminal(
            [
                ("0x1000", "mov eax, [ebx] ; ret"),
                ("0x1004", "mov [eax], ecx ; ret"),
                ("0x1008", "mov [ebx+0x20], eax ; ret"),
            ]
        )

    def test_deref(self, term):
        results = term.execute("deref ebx")
        assert any("mov eax, [ebx]" in g.raw for g in results)

    def test_read_alias(self, term):
        results = term.execute("read ebx")
        assert any("mov eax, [ebx]" in g.raw for g in results)

    def test_memoff(self, term):
        results = term.execute("memoff ebx+0x20")
        assert any("ebx+0x20" in g.raw for g in results)


class TestStackCommands:
    @pytest.fixture
    def term(self):
        return _make_terminal(
            [
                ("0x1000", "pop eax ; ret"),
                ("0x1004", "pop eax ; pop ebx ; ret"),
                ("0x1008", "push eax ; ret"),
                ("0x100c", "xchg eax, esp ; ret"),
                ("0x1010", "mov esp, eax ; ret"),
            ]
        )

    def test_pop(self, term):
        results = term.execute("pop eax")
        assert len(results) >= 1

    def test_push(self, term):
        results = term.execute("push eax")
        assert any("push eax" in g.raw for g in results)

    def test_ppr(self, term):
        results = term.execute("ppr")
        assert any("pop eax ; pop ebx ; ret" in g.raw for g in results)


class TestHelpAndToggles:
    def test_help_produces_output(self, capsys):
        term = _make_terminal([])
        term.execute("help")
        output = capsys.readouterr().out
        assert "Search" in output
        assert "Register Operations" in output

    def test_list_returns_all(self):
        term = _make_terminal(
            [
                ("0x1000", "pop eax ; ret"),
                ("0x1004", "pop ebx ; ret"),
            ]
        )
        results = term.execute("list")
        assert len(results) == 2

    def test_toggle_offset(self, capsys):
        term = _make_terminal([])
        assert term._with_base_address is False
        term.execute("offset")
        assert term._with_base_address is True
        term.execute("offset")
        assert term._with_base_address is False

    def test_change_style(self, capsys):
        term = _make_terminal([])
        term.execute("style python")
        from ropcatalog.core.formatters import PythonFormatter

        assert isinstance(term._formatter, PythonFormatter)


class TestRequiresArgDecorator:
    def test_decorator_sets_flag(self):
        @requires_arg
        def sample_cmd(self, arg):
            pass

        assert sample_cmd._requires_arg is True

    def test_undecorated_has_no_flag(self):
        def sample_cmd(self, arg):
            pass

        assert not hasattr(sample_cmd, "_requires_arg")
