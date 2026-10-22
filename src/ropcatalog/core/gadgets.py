# ropcatalog/core/gadgets.py

# Built-in imports
import hashlib
import json
import re
from pathlib import Path
import time
from typing import Union, List, TextIO

# Local imports
from . import registers
from . import semantics

def sort_key(gadget: 'Gadget') -> tuple:
    return (
        gadget.semantics["quality"]["score"], gadget.module or "",
        gadget.source_id or "", int(gadget.address, 16), gadget.raw,
    )


class Gadget:
    UNSTABLE_OPS = {
        # Conditional jumps (unsigned)
        "ja", "jae", "jb", "jbe",
        "jna", "jnae", "jnb", "jnbe",

        # Conditional jumps (signed)
        "jg", "jge", "jl", "jle",
        "jng", "jnge", "jnl", "jnle",

        # Conditional jumps (flags)
        "jz", "jnz", "je", "jne",
        "jo", "jno", "js", "jns",
        "jp", "jnp", "jpe", "jpo",

        # Conditional jumps (counter)
        "jecxz", "jrcxz",

        # Unconditional control flow
        "loop", "loopne", "loope",

        # Interrupts and traps
        "int3", "int1", "int ", "into", "ud2",

        # System control (privileged)
        "hlt", "cli", "sti",

        # I/O operations (privileged)
        "in ", "out ", "ins", "outs",

        # VM instructions (privileged)
        "vmcall", "vmlaunch", "vmresume", "vmxoff", "vmxon", "vmfunc",

        # Repeat prefixes (unpredictable iteration)
        "rep ", "repe ", "repz ", "repne ", "repnz ",
    }

    MAX_RETN = 0x28  # 40 bytes (5 QWORDs on x64)

    @staticmethod
    def instruction_string_to_list(instruction_string: str) -> list:
        return [instruction.strip() for instruction in instruction_string.split(";") if instruction.strip()]

    def __init__(
        self,
        address: str,
        raw_string: str,
        module: str = None,
        arch: str = 'x86',
        source_id: str | None = None,
        bytes_hex: str | None = None,
        address_kind: str = "unknown",
        extractor: str = "unknown",
        extractor_version: str | None = None,
        source_sha256: str | None = None,
    ):
        self._arch = arch.lower()
        self._address = f"0x{int(address, 16):x}"
        self._module = module
        self._source_id = source_id or module
        self._address_kind = address_kind
        self._extractor = extractor
        self._extractor_version = extractor_version
        self._source_sha256 = source_sha256 or source_id
        normalized = re.sub(r"\s{2,}", " ", raw_string.strip().lower())
        dump_match = re.search(r"\s+//\s*([0-9a-f]+)$", normalized)
        rp_bytes_match = re.search(r"(?:;\s*)?((?:\\x[0-9a-f]{2})+)$", normalized)
        extracted_bytes = dump_match.group(1) if dump_match else None
        if rp_bytes_match:
            extracted_bytes = rp_bytes_match.group(1).replace("\\x", "")
        self._bytes_hex = bytes_hex or extracted_bytes
        if dump_match:
            normalized = normalized[:dump_match.start()].strip()
        elif rp_bytes_match:
            normalized = normalized[:rp_bytes_match.start()].strip()
        self._instructions = Gadget.instruction_string_to_list(instruction_string=normalized)
        self._raw = " ; ".join(self._instructions)
        self._semantics = semantics.analyze(self._instructions, self._arch)


    def uses_only_volatile_regs(self) -> bool:
        """Check if gadget only uses volatile (caller-saved) registers"""

        nonvolatile = registers.get_nonvolatile_registers(self._arch)

        # Check if any non-volatile register appears in the gadget
        for nv_reg in nonvolatile:
            if re.search(rf'\b{nv_reg}\b', self._raw, re.IGNORECASE):
                return False

        return True

    def is_register_modified(self, reg: str, instructions: list) -> bool:
        """Check if register or its sub-registers are modified"""

        sub_registers = registers.get_sub_registers(self._arch)
        canonical = registers.canonical_register(reg, self._arch)
        registers_to_check = sub_registers.get(canonical, [canonical])

        for instr in instructions:
            instr_lower = instr.strip().lower()
            mnemonic = instr_lower.split(maxsplit=1)[0]

            implicit_writes = {
                "cpuid": {"rax", "rbx", "rcx", "rdx", "eax", "ebx", "ecx", "edx"},
                "div": {"rax", "rdx", "eax", "edx"},
                "idiv": {"rax", "rdx", "eax", "edx"},
                "rdtsc": {"rax", "rdx", "eax", "edx"},
                "rdtscp": {"rax", "rcx", "rdx", "eax", "ecx", "edx"},
            }
            if canonical in implicit_writes.get(mnemonic, set()):
                return True

            # Check for pop instruction
            if instr_lower.startswith("pop "):
                parts = instr_lower.split()
                if len(parts) >= 2 and parts[1].strip() in registers_to_check:
                    return True

            # Check for xchg (modifies both operands)
            if instr_lower.startswith("xchg "):
                for reg_check in registers_to_check:
                    if re.search(rf'\b{reg_check}\b', instr_lower):
                        return True

            # Check for single-operand modifying instructions
            for modifier in registers.SINGLE_OPERAND_MODIFIERS:
                if instr_lower.startswith(modifier + " "):
                    parts = instr_lower.split()
                    if len(parts) >= 2:
                        operand = parts[1].strip()
                        if operand in registers_to_check:
                            return True

            # Check for comma-separated instructions (dest is before comma)
            if "," in instr_lower:
                dest = instr_lower.split(",")[0].strip().split()[-1]
                if dest in registers_to_check:
                    return True

        return False

    def has_unstable_op(self) -> bool:
        """Check if gadget contains unstable/unpredictable operations"""

        # Check standard unstable ops (without "call")
        for op in self.UNSTABLE_OPS:
            if op in self._raw:
                return True

        for instruction in self._instructions:
            mnemonic = instruction.split(maxsplit=1)[0]
            if mnemonic in {"call", "jmp"} and not self._is_controlled_transfer(instruction):
                return True

        # Check for large retn values
        if match := re.search(r"\bret(?:n)?\s+0x([0-9a-fA-F]+)", self._raw):
            if int(match.group(1), 16) > self.MAX_RETN:
                return True

        # Special case: iretq is only useful with swapgs
        if re.search(r"\biretq?\b", self._raw, re.IGNORECASE):
            if not re.search(r"swapgs\s*;\s*iretq?", self._raw, re.IGNORECASE):
                return True

        return False

    def _is_controlled_transfer(self, instruction: str) -> bool:
        target = instruction.split(maxsplit=1)[1] if " " in instruction else ""
        return any(
            registers.is_register(register, self._arch)
            for register in re.findall(r"\b[a-z][a-z0-9]*\b", target)
        )

    def has_bad_chars_in_address(self, bad_chars: list) -> bool:
        address = self._address[2:]
        width = 16 if self._arch == "x64" else 8
        address = address.zfill(max(width, len(address) + len(address) % 2))
        for byte in [address[index: index + 2] for index in range(0, len(address), 2)]:
            if byte in bad_chars:
                return True
        return False

    def verify_push_coherence(self, target_register: str) -> bool:
        pushed = []
        for instr in self._instructions:
            parts = instr.split()
            if len(parts) != 2:
                continue
            cmd, reg = parts[0].strip(), parts[1].strip()
            if cmd == "push":
                pushed.append(reg)
            elif cmd == "pop" and pushed and pushed.pop() == target_register:
                return True
        return False

    def exact_match(self, search_term: str) -> bool:
        return Gadget.instruction_string_to_list(search_term) == self._instructions

    def partial_match(self, search_term: str) -> bool:
        return all(op in self._raw for op in Gadget.instruction_string_to_list(search_term))

    def regex(self, patterns: Union[str, list[str]]) -> bool:
        if isinstance(patterns, str):
            patterns = [patterns]
        return any(re.search(p, self._raw, re.IGNORECASE) for p in patterns)

    def pattern_match(self, patterns: Union[str, list[str]]) -> list[re.Match]:
        if isinstance(patterns, str):
            patterns = [patterns]
        matches = []
        for p in patterns:
            matches.extend(re.finditer(p, self._raw, re.IGNORECASE))
        return matches

    def pythonic_string(self, with_base_address: bool = False) -> str:
        header = 'rop += pack("<L", '
        if with_base_address:
            header += f"ba__{self._module} + "
        header += self._address
        return header + f") # {self._raw} [{self._module}]"

    def javascript_string(self, with_base_address: bool = False) -> str:
        """
        Returns a JavaScript-style gadget representation:
        writePtr(ropBuffer + ropIndex * 8, <base> + <offset>); ropIndex++; // <gadget> [<module>]
        """
        base_expr = f"g{self._module}Base + " if with_base_address else ""
        return f"writePtr(ropBuffer + ropIndex * 8, {base_expr}{self._address}); ropIndex++; // {self._raw} [{self._module}]"


    def __str__(self):
        return f"{self._address} # {self._raw} [{self._module}]"

    def __repr__(self):
        return f"Gadget({self._address}, {self._raw}, {self._instructions})"

    @property
    def module(self) -> str:
        return self._module

    @property
    def raw(self) -> str:
        return self._raw


    @property
    def address(self) -> str:
        return self._address

    @property
    def instructions(self) -> list:
        return self._instructions

    @property
    def arch(self) -> str:
        return self._arch

    @property
    def semantics(self) -> dict:
        return self._semantics

    @property
    def source_id(self) -> str:
        return self._source_id

    @property
    def bytes_hex(self) -> str | None:
        return self._bytes_hex

    @property
    def address_kind(self) -> str:
        return self._address_kind

    @property
    def identifier(self) -> str:
        identity = f"{self._source_id}\0{self._arch}\0{self._address}\0{self._raw}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

    @property
    def extractor(self) -> str:
        return self._extractor

    @property
    def extractor_version(self) -> str | None:
        return self._extractor_version

    @property
    def source_sha256(self) -> str | None:
        return self._source_sha256


class Gadgets:
    def __init__(
        self,
        file_paths: List[str],
        bad_chars: list = None,
        encoding: str | None = None,
        input_stream: TextIO | None = None,
        input_module: str = "stdin",
        address_kind: str = "unknown",
    ):
        self._bad_characters = bad_chars
        self._encoding = encoding
        self._unique_mode = True
        self._address_kind = address_kind

        all_gadgets = []
        for file_path in file_paths:
            path = Path(file_path).resolve()
            if not path.is_file():
                print(f"[!] File {file_path} does not exist.")
                continue
            all_gadgets.extend(self._parse_file(path))
        if input_stream is not None:
            all_gadgets.extend(self._parse_text(input_stream.read(), input_module))

        # Store full list (all gadgets including bad ones)
        self._full_list = list(all_gadgets)

        # Filter bad gadgets
        bad_count = 0
        clean_gadgets = []
        for gadget in all_gadgets:
            if gadget.has_unstable_op():
                bad_count += 1
            else:
                clean_gadgets.append(gadget)

        # Active list is what's used by iteration (unique by default)
        self._active_list = self._filter_unique(clean_gadgets)

        print(f"\n[+] Total gadgets loaded: {len(self._full_list)}")
        print(f"|-> Stable gadgets: {len(clean_gadgets)}")
        print(f"|-> Unique gadgets (active): {len(self._active_list)}")
        print(f"|-> Unstable gadgets (filtered): {bad_count}")

    def use_full_catalog(self, enabled: bool):
        """Temporarily switch between clean and full catalog"""
        if enabled:
            self._active_list = self._full_list
        else:
            # Restore based on uniqueness mode
            if self._unique_mode:
                clean_gadgets = [g for g in self._full_list if not g.has_unstable_op()]
                self._active_list = self._filter_unique(clean_gadgets)
            else:
                self._active_list = [g for g in self._full_list if not g.has_unstable_op()]

    def __iter__(self):
        return iter(self._active_list)

    def __len__(self):
        return len(self._active_list)

    def add_gadget(self, gadget: Gadget) -> None:
        if isinstance(gadget, Gadget):
            self._active_list.append(gadget)
        else:
            raise TypeError("Only Gadget objects can be added.")

    def set_uniqueness(self, enabled: bool):
        self._unique_mode = enabled

        # Always start with clean gadgets
        clean_gadgets = [g for g in self._full_list if not g.has_unstable_op()]

        if enabled:
            self._active_list = self._filter_unique(clean_gadgets)  # Filter unique from CLEAN list
        else:
            self._active_list = clean_gadgets  # Use all CLEAN gadgets

        print(f"[+] Uniqueness mode {'enabled' if enabled else 'disabled'} ({len(self._active_list)} gadgets)")

    def _filter_unique(self, gadgets_list):
        """Filter for unique gadgets per module (same instruction, different addresses within same module)"""
        seen = {}
        for g in gadgets_list:
            # Key by both module and raw instruction
            key = (g.source_id, g.module, g.raw)
            if key not in seen:
                seen[key] = g
        return list(seen.values())

    def _parse_file(self, file_path: str) -> list:
        from .utils import detect_file_encoding

        encoding = self._encoding
        if not encoding:
            encoding = detect_file_encoding(file_path)

        try:
            with open(file_path, mode="r", encoding=encoding) as file_obj:
                file_content = file_obj.read()
        except UnicodeDecodeError:
            print(f"[!] Failed to decode '{file_path.name}' with encoding '{encoding}'.")
            print("[!] Try specifying a different encoding with --encoding.")
            return []

        return self._parse_text(file_content, file_path.stem)

    def _parse_text(self, file_content: str, module: str) -> list:
        file_content = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", file_content)
        if '"schema":"ropcatalog.catalog.v1"' in file_content:
            return self._parse_catalog(file_content)

        gadget_pattern = re.compile(
            r"^\s*(0x[0-9a-fA-F]+)\s*:\s*(.+?)\s*(?:\(\d+\sfound\))?\s*$",
            re.MULTILINE,
        )
        start_time = time.time()

        from .utils import detect_arch_from_text

        arch = detect_arch_from_text(file_content)
        print(f"[+] Detected architecture: {arch}")

        bad_char_count = 0
        results = []
        source_sha256 = hashlib.sha256(file_content.encode("utf-8")).hexdigest()
        source_id = source_sha256[:16]
        extractor, extractor_version = _detect_extractor(file_content)

        for match in gadget_pattern.finditer(file_content):
            gadget = Gadget(
                address=match.group(1),
                raw_string=match.group(2).strip().lower(),
                module=module,
                arch=arch,
                source_id=source_id,
                address_kind=self._address_kind,
                extractor=extractor,
                extractor_version=extractor_version,
                source_sha256=source_sha256,
            )
            if self._bad_characters and gadget.has_bad_chars_in_address(self._bad_characters):
                bad_char_count += 1
                continue
            results.append(gadget)

        elapsed_time = time.time() - start_time

        print(f"\n[+] {module} parsed in {elapsed_time:.2f}s")
        print(f"|-> Total gadgets extracted: {len(results)}")
        print(f"|-> Gadgets containing bad characters: {bad_char_count}")
        return results

    def _parse_catalog(self, file_content: str) -> list:
        results = []
        for line_number, line in enumerate(file_content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if record.get("schema") != "ropcatalog.catalog.v1":
                    raise ValueError("unexpected schema")
                gadget = Gadget(
                    address=record["address"],
                    raw_string=record["raw"],
                    module=record["module"],
                    arch=record["arch"],
                    source_id=record["source_id"],
                    bytes_hex=record.get("bytes"),
                    address_kind=record.get("address_kind", "unknown"),
                    extractor=record.get("extractor", "unknown"),
                    extractor_version=record.get("extractor_version"),
                    source_sha256=record.get("source_sha256"),
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                raise ValueError(f"invalid catalog record on line {line_number}: {error}") from error
            if self._bad_characters and gadget.has_bad_chars_in_address(self._bad_characters):
                continue
            results.append(gadget)
        print(f"[+] Loaded reusable catalog with {len(results)} gadget(s)")
        return results

    def write_catalog(self, path: Path) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(
            self._full_list,
            key=lambda gadget: (gadget.module, gadget.source_id, int(gadget.address, 16), gadget.raw),
        )
        with path.open("w", encoding="utf-8") as stream:
            for gadget in ordered:
                record = {
                    "schema": "ropcatalog.catalog.v1",
                    "source_id": gadget.source_id,
                    "module": gadget.module,
                    "address": gadget.address,
                    "address_kind": gadget.address_kind,
                    "arch": gadget.arch,
                    "extractor": gadget.extractor,
                    "raw": gadget.raw,
                }
                if gadget.extractor_version is not None:
                    record["extractor_version"] = gadget.extractor_version
                if gadget.source_sha256 is not None:
                    record["source_sha256"] = gadget.source_sha256
                if gadget.bytes_hex is not None:
                    record["bytes"] = gadget.bytes_hex
                print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=stream)
        return len(ordered)

    def to_dict(self) -> dict:
        return {g.address: g.raw for g in self._active_list}

    @property
    def gadgets(self) -> list:
        return self._active_list

    @property
    def full_count(self) -> int:
        return len(self._full_list)


def _detect_extractor(file_content: str) -> tuple[str, str | None]:
    version_match = re.search(r"rp\+\+\s+v(?:ersion\s*)?([0-9][^\s.]*(?:\.[0-9]+)*)", file_content, re.IGNORECASE)
    if "rp++" in file_content.lower() or "you decided to keep only the unique ones" in file_content.lower():
        return "rp++", version_match.group(1) if version_match else None
    if "ropgadget" in file_content.lower() or "gadgets information" in file_content.lower():
        return "ROPgadget", None
    if "ropper" in file_content.lower() or "gadgets\n=======\n" in file_content.lower():
        return "Ropper", None
    return "unknown", None

