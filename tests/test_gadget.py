# tests/test_gadget.py

"""Tests for the Gadget class: construction, matching, stability, and bad char filtering."""

import pytest
from ropcatalog.core.gadgets import Gadget, sort_key


class TestGadgetConstruction:
    """Test Gadget object creation and property access."""

    def test_address_normalized(self, make_gadget):
        g = make_gadget(address="0x0010001000")
        assert g.address == "0x10001000"

    def test_raw_normalized(self, make_gadget):
        g = make_gadget(raw="  POP   EAX ;  RET  ")
        assert g.raw == "pop eax ; ret"

    def test_instructions_split(self, make_gadget):
        g = make_gadget(raw="pop eax ; pop ebx ; ret")
        assert g.instructions == ["pop eax", "pop ebx", "ret"]

    def test_module_stored(self, make_gadget):
        g = make_gadget(module="kernel32")
        assert g.module == "kernel32"

    def test_arch_stored(self, make_gadget):
        g = make_gadget(arch="x64")
        assert g.arch == "x64"

    def test_str(self, make_gadget):
        g = make_gadget(address="0x10001000", raw="pop eax ; ret", module="testmod")
        assert "0x10001000" in str(g)
        assert "pop eax ; ret" in str(g)
        assert "testmod" in str(g)

    def test_repr(self, make_gadget):
        g = make_gadget()
        assert "Gadget(" in repr(g)


class TestInstructionParsing:
    def test_instruction_string_to_list(self):
        result = Gadget.instruction_string_to_list("pop eax ; pop ebx ; ret")
        assert result == ["pop eax", "pop ebx", "ret"]

    def test_instruction_string_to_list_empty_parts(self):
        result = Gadget.instruction_string_to_list("pop eax ;; ret")
        assert result == ["pop eax", "ret"]

    def test_instruction_string_to_list_single(self):
        result = Gadget.instruction_string_to_list("ret")
        assert result == ["ret"]


class TestExactMatch:
    def test_exact_match_true(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        assert g.exact_match("pop eax ; ret") is True

    def test_exact_match_false(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        assert g.exact_match("pop ebx ; ret") is False

    def test_exact_match_subset_false(self, make_gadget):
        g = make_gadget(raw="pop eax ; pop ebx ; ret")
        assert g.exact_match("pop eax ; ret") is False


class TestPartialMatch:
    def test_partial_match_single(self, make_gadget):
        g = make_gadget(raw="pop eax ; pop ebx ; ret")
        assert g.partial_match("pop eax") is True

    def test_partial_match_multiple(self, make_gadget):
        g = make_gadget(raw="pop eax ; pop ebx ; ret")
        assert g.partial_match("pop eax ; ret") is True

    def test_partial_match_false(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        assert g.partial_match("pop ecx") is False


class TestRegexMatch:
    def test_regex_match(self, make_gadget):
        g = make_gadget(raw="mov eax, ecx ; ret")
        assert g.regex(r"mov eax, \w+") is True

    def test_regex_no_match(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        assert g.regex(r"mov.*") is False

    def test_regex_list(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        assert g.regex([r"mov.*", r"pop eax"]) is True


class TestPatternMatch:
    def test_pattern_match_returns_matches(self, make_gadget):
        g = make_gadget(raw="mov eax, ecx ; ret")
        matches = g.pattern_match(r"mov (\w+), (\w+)")
        assert len(matches) >= 1
        assert matches[0].group(1) == "eax"
        assert matches[0].group(2) == "ecx"

    def test_pattern_match_no_match(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret")
        matches = g.pattern_match(r"mov (\w+), (\w+)")
        assert len(matches) == 0


class TestUnstableOps:
    @pytest.mark.parametrize("raw", [
        "jmp eax ; ret",
        "int3 ; ret",
        "hlt ; ret",
        "jz label ; ret",
        "loop start ; ret",
    ])
    def test_unstable_ops_detected(self, make_gadget, raw):
        g = make_gadget(raw=raw)
        assert g.has_unstable_op() is True

    @pytest.mark.parametrize("raw", [
        "pop eax ; ret",
        "mov eax, ecx ; ret",
        "xor eax, eax ; ret",
        "add eax, ecx ; ret",
        "nop ; ret",
    ])
    def test_stable_ops(self, make_gadget, raw):
        g = make_gadget(raw=raw)
        assert g.has_unstable_op() is False

    def test_large_retn_unstable(self, make_gadget):
        g = make_gadget(raw="pop eax ; retn 0x100")
        assert g.has_unstable_op() is True

    def test_small_retn_stable(self, make_gadget):
        g = make_gadget(raw="pop eax ; retn 0x04")
        assert g.has_unstable_op() is False

    def test_call_direct_unstable(self, make_gadget):
        g = make_gadget(raw="call 0x12345 ; ret")
        assert g.has_unstable_op() is True

    def test_call_indirect_rax_stable(self, make_gadget):
        g = make_gadget(raw="call rax ; ret", arch="x64")
        assert g.has_unstable_op() is False

    def test_iretq_without_swapgs_unstable(self, make_gadget):
        g = make_gadget(raw="iretq", arch="x64")
        assert g.has_unstable_op() is True

    def test_swapgs_iretq_stable(self, make_gadget):
        g = make_gadget(raw="swapgs ; iretq", arch="x64")
        assert g.has_unstable_op() is False


class TestBadChars:
    def test_bad_chars_in_address(self, make_gadget):
        g = make_gadget(address="0x100a1000")
        assert g.has_bad_chars_in_address(["0a"]) is True

    def test_no_bad_chars_in_address(self, make_gadget):
        g = make_gadget(address="0x10001000")
        assert g.has_bad_chars_in_address(["0a"]) is False

    def test_multiple_bad_chars(self, make_gadget):
        g = make_gadget(address="0x100d1000")
        assert g.has_bad_chars_in_address(["0a", "0d"]) is True

    def test_empty_bad_chars(self, make_gadget):
        g = make_gadget(address="0x100a1000")
        assert g.has_bad_chars_in_address([]) is False


class TestPushCoherence:
    def test_push_pop_coherent(self, make_gadget):
        g = make_gadget(raw="push eax ; pop eax ; ret")
        assert g.verify_push_coherence("eax") is True

    def test_push_pop_target_was_pushed(self, make_gadget):
        # verify_push_coherence checks if the pushed register == target
        # "push eax ; pop ebx" -> pushed "eax", pop pops "eax", target="eax" -> True
        g = make_gadget(raw="push eax ; pop ebx ; ret")
        assert g.verify_push_coherence("eax") is True

    def test_push_pop_target_not_pushed(self, make_gadget):
        # "push esp ; pop eax" -> pushed "esp", pop pops "esp", target="eax" -> False
        g = make_gadget(raw="push esp ; pop eax ; ret")
        assert g.verify_push_coherence("eax") is False

    def test_push_pop_target_matches_pushed(self, make_gadget):
        g = make_gadget(raw="push esp ; pop eax ; ret")
        assert g.verify_push_coherence("esp") is True


class TestRegisterModified:
    def test_pop_modifies(self, make_gadget):
        g = make_gadget(arch="x86")
        assert g.is_register_modified("eax", ["pop eax"]) is True

    def test_pop_different_reg(self, make_gadget):
        g = make_gadget(arch="x86")
        assert g.is_register_modified("eax", ["pop ebx"]) is False

    def test_xchg_modifies_both(self, make_gadget):
        g = make_gadget(arch="x86")
        assert g.is_register_modified("eax", ["xchg eax, ebx"]) is True
        assert g.is_register_modified("ebx", ["xchg eax, ebx"]) is True

    def test_comma_instruction_modifies_dest(self, make_gadget):
        g = make_gadget(arch="x86")
        assert g.is_register_modified("eax", ["mov eax, ecx"]) is True
        assert g.is_register_modified("ecx", ["mov eax, ecx"]) is False

    def test_sub_register_detected(self, make_gadget):
        g = make_gadget(arch="x64")
        assert g.is_register_modified("rax", ["pop eax"]) is True

    def test_inc_modifies(self, make_gadget):
        g = make_gadget(arch="x86")
        assert g.is_register_modified("eax", ["inc eax"]) is True


class TestVolatileRegs:
    def test_volatile_only_x64(self, make_gadget):
        g = make_gadget(raw="pop rax ; ret", arch="x64")
        assert g.uses_only_volatile_regs() is True

    def test_nonvolatile_detected_x64(self, make_gadget):
        g = make_gadget(raw="pop rbx ; ret", arch="x64")
        assert g.uses_only_volatile_regs() is False

    def test_volatile_only_x86(self, make_gadget):
        g = make_gadget(raw="pop eax ; ret", arch="x86")
        assert g.uses_only_volatile_regs() is True


class TestSortKey:
    def test_sort_by_instruction_count(self, make_gadget):
        g1 = make_gadget(raw="pop eax ; ret")
        g2 = make_gadget(raw="pop eax ; pop ebx ; ret")
        assert sort_key(g1) < sort_key(g2)

    def test_retn_penalized(self, make_gadget):
        g1 = make_gadget(raw="pop eax ; ret")
        g2 = make_gadget(raw="pop eax ; retn 0x04")
        assert sort_key(g1) < sort_key(g2)
