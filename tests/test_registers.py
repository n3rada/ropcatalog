# tests/test_registers.py

"""Tests for register definitions and helper functions."""

from ropcatalog.core.registers import (
    X86_REGISTERS,
    X64_REGISTERS,
    X64_ADDITIONAL_REGISTERS,
    VOLATILE_X86,
    VOLATILE_X64,
    NONVOLATILE_X86,
    NONVOLATILE_X64,
    SUB_REGISTERS_X86,
    SUB_REGISTERS_X64,
    SINGLE_OPERAND_MODIFIERS,
    get_registers,
    get_volatile_registers,
    get_nonvolatile_registers,
    get_sub_registers,
    is_register,
)


class TestRegisterSets:
    def test_x86_contains_common_regs(self):
        for reg in ("eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi"):
            assert reg in X86_REGISTERS

    def test_x86_contains_16bit(self):
        for reg in ("ax", "bx", "cx", "dx"):
            assert reg in X86_REGISTERS

    def test_x86_contains_8bit(self):
        for reg in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"):
            assert reg in X86_REGISTERS

    def test_x64_superset_of_x86(self):
        assert X86_REGISTERS.issubset(X64_REGISTERS)

    def test_x64_has_extended_regs(self):
        for i in range(8, 16):
            assert f"r{i}" in X64_REGISTERS
            assert f"r{i}d" in X64_REGISTERS
            assert f"r{i}w" in X64_REGISTERS
            assert f"r{i}b" in X64_REGISTERS

    def test_x64_has_64bit_gp(self):
        for reg in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi"):
            assert reg in X64_REGISTERS


class TestVolatileNonvolatile:
    def test_volatile_x86_does_not_overlap_nonvolatile(self):
        assert VOLATILE_X86.isdisjoint(NONVOLATILE_X86)

    def test_volatile_x64_does_not_overlap_nonvolatile(self):
        assert VOLATILE_X64.isdisjoint(NONVOLATILE_X64)

    def test_volatile_x86_has_caller_saved(self):
        for reg in ("eax", "ecx", "edx"):
            assert reg in VOLATILE_X86

    def test_nonvolatile_x86_has_callee_saved(self):
        for reg in ("ebx", "ebp", "esi", "edi"):
            assert reg in NONVOLATILE_X86

    def test_volatile_x64_includes_r8_r11(self):
        for i in range(8, 12):
            assert f"r{i}" in VOLATILE_X64

    def test_nonvolatile_x64_includes_r12_r15(self):
        for i in range(12, 16):
            assert f"r{i}" in NONVOLATILE_X64


class TestSubRegisters:
    def test_x86_eax_mapping(self):
        assert SUB_REGISTERS_X86["eax"] == ["eax", "ax", "al", "ah"]

    def test_x64_rax_mapping(self):
        assert SUB_REGISTERS_X64["rax"] == ["rax", "eax", "ax", "al", "ah"]

    def test_x64_extended_reg_mapping(self):
        assert SUB_REGISTERS_X64["r8"] == ["r8", "r8d", "r8w", "r8b"]

    def test_all_x86_gp_covered(self):
        for reg in ("eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi"):
            assert reg in SUB_REGISTERS_X86

    def test_all_x64_gp_covered(self):
        for reg in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi"):
            assert reg in SUB_REGISTERS_X64
        for i in range(8, 16):
            assert f"r{i}" in SUB_REGISTERS_X64


class TestHelperFunctions:
    def test_get_registers_x86(self):
        assert get_registers("x86") == X86_REGISTERS

    def test_get_registers_x64(self):
        assert get_registers("x64") == X64_REGISTERS

    def test_get_registers_case_insensitive(self):
        assert get_registers("X64") == X64_REGISTERS

    def test_get_volatile_registers_x86(self):
        assert get_volatile_registers("x86") == VOLATILE_X86

    def test_get_volatile_registers_x64(self):
        assert get_volatile_registers("x64") == VOLATILE_X64

    def test_get_nonvolatile_registers_x86(self):
        assert get_nonvolatile_registers("x86") == NONVOLATILE_X86

    def test_get_nonvolatile_registers_x64(self):
        assert get_nonvolatile_registers("x64") == NONVOLATILE_X64

    def test_get_sub_registers_x86(self):
        assert get_sub_registers("x86") == SUB_REGISTERS_X86

    def test_get_sub_registers_x64(self):
        assert get_sub_registers("x64") == SUB_REGISTERS_X64

    def test_is_register_true(self):
        assert is_register("eax", "x86") is True
        assert is_register("rax", "x64") is True

    def test_is_register_false(self):
        assert is_register("0x123", "x86") is False
        assert is_register("notareg", "x64") is False

    def test_is_register_extended(self):
        assert is_register("r15", "x64") is True
        assert is_register("r15d", "x64") is True


class TestSingleOperandModifiers:
    def test_expected_modifiers(self):
        expected = {"inc", "dec", "neg", "not", "push", "pop", "bswap"}
        assert expected == SINGLE_OPERAND_MODIFIERS
