from pathlib import Path

import pytest

from ropcatalog.core.gadgets import Gadgets


EXAMPLES = Path(__file__).parents[1] / "examples" / "windows-11-enterprise-10.0.22631"


@pytest.mark.parametrize(
    ("module", "expected_count", "expected_raw", "expected_bytes"),
    [
        ("ntoskrnl.exe", 17, "mov cr4, rcx ; ret", "0f22e1c3"),
        ("win32kfull.sys", 14, "pop rcx ; ret", "59c3"),
        ("clfs.sys", 18, "pop rcx ; pop rdx ; pop r8 ; pop r9 ; ret", "595a41584159c3"),
        ("afd.sys", 13, "pop rcx ; ret", "59c3"),
        ("ntdll.dll", 15, "syscall ; ret", "0f05c3"),
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
