from pathlib import Path

import pytest

from ropcatalog.core.gadgets import Gadgets
from ropcatalog.core.terminal import Terminal


EXAMPLES = Path(__file__).parents[1] / "examples" / "windows-11-enterprise-10.0.22631"

COMMAND_CASES = [
    ("list", "pop rcx ; ret"),
    ("? pop rcx ; ret", "pop rcx ; ret"),
    ("/ pop rcx", "pop rcx ; ret"),
    (". ^pop rcx ; ret$", "pop rcx ; ret"),
    ("memoff rdx+0x38", "mov eax, [rdx+0x38] ; ret"),
    ("copy rax", "push rax ; pop rdi ; ret"),
    ("copyto rax", "mov rax, r10 ; ret"),
    ("mov rax", "mov rax, r10 ; ret"),
    ("save rax", "push rax ; pop rdi ; ret"),
    ("saveto rax reg", "mov rax, r10 ; ret"),
    ("swap rax", "xchg rax, rbp ; dec [rax-0x75] ; ret"),
    ("zero rax", "xor rax, rax ; ret"),
    ("inc rax", "add rax, 0x0000000000001500 ; ret"),
    ("dec rax", "dec rax ; ret"),
    ("add rax rcx", "add rax, rcx ; ret"),
    ("sub rax rcx", "sub rax, rcx ; ret"),
    ("read rax", "mov rax, qword [rax] ; ret"),
    ("deref rax", "mov rax, qword [rax] ; ret"),
    ("writereg rcx", "mov qword [rdx+0x08], rcx ; ret"),
    ("writeptr rax", "mov [rax], edx ; ret"),
    ("writebyte rax", "mov byte [rax], al ; ret"),
    ("addmem rax", "add [rax], eax ; ret"),
    ("submem rcx", "sub [rcx], eax ; ret"),
    ("incmem rax", "inc [rax] ; ret"),
    ("decmem rax", "dec [rax] ; ret"),
    ("push rax", "push rax ; ret"),
    ("pop rax", "pop rax ; ret"),
    ("ppr", "pop rsp ; pop rdi ; ret"),
    ("pivot reg", "mov rsp, r11 ; ret"),
    ("jump rsp", "call rsp"),
    ("call rax", "call rax"),
    ("ret", "ret"),
    ("transition", "swapgs ; iretq"),
    ("syscall", "syscall ; ret"),
    ("loadcr rcx", "mov cr4, rcx ; ret"),
    ("nop", "nop ; ret"),
    ("funcnop", "mov r14l, r14l ; ret"),
]


@pytest.fixture(scope="module")
def real_windows_terminal():
    return Terminal(Gadgets(sorted(EXAMPLES.glob("*.txt")), address_kind="rva"))


@pytest.mark.parametrize(
    ("module", "expected_count", "expected_raw", "expected_bytes"),
    [
        ("ntoskrnl.exe", 19, "mov cr4, rcx ; ret", "0f22e1c3"),
        ("win32kfull.sys", 15, "pop rcx ; ret", "59c3"),
        ("clfs.sys", 26, "pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret", "595a41584159c3"),
        ("afd.sys", 13, "pop rcx ; ret", "59c3"),
        ("ntdll.dll", 25, "syscall ; ret", "0f05c3"),
        ("kernel32.dll", 12, "mov qword [rdx], rcx ; ret", "48890ac3"),
    ],
)
def test_real_windows_rp_examples(module, expected_count, expected_raw, expected_bytes):
    catalog = Gadgets([EXAMPLES / f"{module}.txt"], address_kind="rva")
    catalog.use_full_catalog(True)
    gadgets = list(catalog)

    assert catalog.full_count == expected_count
    assert {gadget.arch for gadget in gadgets} == {"x64"}
    assert {gadget.module for gadget in gadgets} == {module}
    assert {gadget.address_kind for gadget in gadgets} == {"rva"}
    assert all(gadget.bytes_hex for gadget in gadgets)
    assert any(
        gadget.raw == expected_raw and gadget.bytes_hex == expected_bytes
        for gadget in gadgets
    )


def test_real_examples_cover_every_retrieval_command(real_windows_terminal):
    covered = {command.split(maxsplit=1)[0] for command, _ in COMMAND_CASES}

    assert covered == real_windows_terminal.query_command_names - {"neg", "not", "popad", "pushad", "writeimm"}


@pytest.mark.parametrize(("command", "expected_raw"), COMMAND_CASES)
def test_retrieval_command_against_real_examples(real_windows_terminal, command, expected_raw):
    results = real_windows_terminal.execute(command)

    assert any(gadget.raw == expected_raw for gadget in results)


def test_real_examples_reject_semantic_false_positives(real_windows_terminal):
    assert all("cr3" not in gadget.raw for gadget in real_windows_terminal.execute("copy rax"))
    assert all("lea eax, [rax" not in gadget.raw for gadget in real_windows_terminal.execute("save rax"))
    assert all(not gadget.raw.startswith("mov es,") for gadget in real_windows_terminal.execute("read rax"))
