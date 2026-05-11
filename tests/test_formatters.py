# tests/test_formatters.py

"""Tests for gadget output formatters."""

import pytest
from ropcatalog.core.gadgets import Gadget
from ropcatalog.core.formatters import (
    PlainFormatter,
    PythonFormatter,
    CppFormatter,
    JavaScriptFormatter,
)


@pytest.fixture
def gadget_x86():
    return Gadget(address="0x10001000", raw_string="pop eax ; ret", module="testmod", arch="x86")


@pytest.fixture
def gadget_x64():
    return Gadget(address="0x7fff00001000", raw_string="pop rax ; ret", module="kernel32", arch="x64")


class TestPlainFormatter:
    def test_format(self, gadget_x86):
        fmt = PlainFormatter()
        result = fmt.format(gadget_x86)
        assert "0x10001000" in result
        assert "pop eax ; ret" in result
        assert "testmod" in result

    def test_format_with_base(self, gadget_x86):
        fmt = PlainFormatter()
        result_no_base = fmt.format(gadget_x86, with_base_address=False)
        result_with_base = fmt.format(gadget_x86, with_base_address=True)
        # PlainFormatter uses str(gadget), so base address flag is ignored
        assert "0x10001000" in result_no_base
        assert "0x10001000" in result_with_base


class TestPythonFormatter:
    def test_format_x86(self, gadget_x86):
        fmt = PythonFormatter()
        result = fmt.format(gadget_x86)
        assert 'pack("<L"' in result
        assert "0x10001000" in result
        assert "pop eax ; ret" in result

    def test_format_x64(self, gadget_x64):
        fmt = PythonFormatter()
        result = fmt.format(gadget_x64)
        assert 'pack("<Q"' in result

    def test_format_with_base_address(self, gadget_x86):
        fmt = PythonFormatter()
        result = fmt.format(gadget_x86, with_base_address=True)
        assert "ba__testmod" in result

    def test_format_without_base_address(self, gadget_x86):
        fmt = PythonFormatter()
        result = fmt.format(gadget_x86, with_base_address=False)
        assert "ba__" not in result


class TestCppFormatter:
    def test_format(self, gadget_x86):
        fmt = CppFormatter()
        result = fmt.format(gadget_x86)
        assert "*rop++" in result
        assert "0x10001000" in result
        assert "pop eax ; ret" in result

    def test_format_with_base_address(self, gadget_x86):
        fmt = CppFormatter()
        result = fmt.format(gadget_x86, with_base_address=True)
        assert "testmodBase" in result

    def test_format_without_base_address(self, gadget_x86):
        fmt = CppFormatter()
        result = fmt.format(gadget_x86, with_base_address=False)
        assert "Base" not in result


class TestJavaScriptFormatter:
    def test_format(self, gadget_x86):
        fmt = JavaScriptFormatter()
        result = fmt.format(gadget_x86)
        assert "writePtr" in result
        assert "ropBuffer" in result
        assert "ropIndex" in result
        assert "0x10001000" in result

    def test_format_with_base_address(self, gadget_x86):
        fmt = JavaScriptFormatter()
        result = fmt.format(gadget_x86, with_base_address=True)
        assert "gTestmod" in result  # CamelCase module name

    def test_format_without_base_address(self, gadget_x86):
        fmt = JavaScriptFormatter()
        result = fmt.format(gadget_x86, with_base_address=False)
        assert "Base" not in result

    def test_camel_case_module(self, gadget_x64):
        fmt = JavaScriptFormatter()
        result = fmt.format(gadget_x64, with_base_address=True)
        assert "gKernel32" in result
