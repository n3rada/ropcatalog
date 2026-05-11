# tests/conftest.py

import pytest
from ropcatalog.core.gadgets import Gadget


@pytest.fixture
def make_gadget():
    """Factory fixture for creating Gadget objects with sensible defaults."""
    def _make(address="0x10001000", raw="pop eax ; ret", module="testmod", arch="x86"):
        return Gadget(address=address, raw_string=raw, module=module, arch=arch)
    return _make


@pytest.fixture
def sample_gadgets_x86(make_gadget):
    """A small collection of x86 gadgets covering common patterns."""
    return [
        make_gadget(address="0x10001000", raw="pop eax ; ret"),
        make_gadget(address="0x10001004", raw="pop ebx ; ret"),
        make_gadget(address="0x10001008", raw="xor eax, eax ; ret"),
        make_gadget(address="0x1000100c", raw="mov eax, ecx ; ret"),
        make_gadget(address="0x10001010", raw="push esp ; pop eax ; ret"),
        make_gadget(address="0x10001014", raw="inc eax ; ret"),
        make_gadget(address="0x10001018", raw="dec eax ; ret"),
        make_gadget(address="0x1000101c", raw="xchg eax, ebx ; ret"),
        make_gadget(address="0x10001020", raw="add eax, ecx ; ret"),
        make_gadget(address="0x10001024", raw="sub eax, ecx ; ret"),
        make_gadget(address="0x10001028", raw="mov [eax], ecx ; ret"),
        make_gadget(address="0x1000102c", raw="mov eax, [ebx] ; ret"),
        make_gadget(address="0x10001030", raw="pop eax ; pop ebx ; ret"),
        make_gadget(address="0x10001034", raw="nop ; ret"),
        make_gadget(address="0x10001038", raw="mov eax, 0x00000000 ; ret"),
    ]


@pytest.fixture
def sample_gadgets_x64(make_gadget):
    """A small collection of x64 gadgets."""
    return [
        make_gadget(address="0x7fff00001000", raw="pop rax ; ret", arch="x64"),
        make_gadget(address="0x7fff00001008", raw="pop rbx ; ret", arch="x64"),
        make_gadget(address="0x7fff00001010", raw="xor rax, rax ; ret", arch="x64"),
        make_gadget(address="0x7fff00001018", raw="mov rax, rcx ; ret", arch="x64"),
        make_gadget(address="0x7fff00001020", raw="syscall ; ret", arch="x64"),
        make_gadget(address="0x7fff00001028", raw="swapgs ; iretq", arch="x64"),
    ]
