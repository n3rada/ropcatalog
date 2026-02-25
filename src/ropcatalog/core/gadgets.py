# ropcatalog/core/gadgets.py

# Built-in imports
import re
from pathlib import Path
import time
from typing import Union, List

# Local imports
from .registers import (
    get_registers,
    get_volatile_registers,
    get_nonvolatile_registers,
    get_sub_registers,
    is_register,
    SINGLE_OPERAND_MODIFIERS
)

def sort_key(gadget: 'Gadget') -> tuple:
    instr_count = len(gadget.instructions)
    # Penalize retn IMM to deprioritize large stack shifts
    if "retn 0x" in gadget.raw:
        return (instr_count + 0.5, int(re.search(r"retn 0x([0-9a-fA-F]+)", gadget.raw).group(1), 16))
    return (instr_count, 0)


class Gadget:
    BAD_OPS = {
        # Control flow
        "int3", "leave", "loop", "loopne", "jmp", "jz", "je", "jnz", "jne",
        "ja", "jae", "jna", "jnae", "jb", "jbe", "jnb", "jnbe",
        
        # System control
        "hlt", "cli", "int ", "into",
        
        # I/O operations
        "in ", "out ", "ins", "outs",
        
        # Undefined/trap
        "ud2", "int1",
        
        # VM instructions
        "vmcall", "vmlaunch", "vmresume", "vmxoff", "vmxon", "vmfunc",
        
        # Repeat prefixes
        "rep ", "repe ", "repz ", "repne ", "repnz ",
    }

    MAX_RETN = 0x28  # 40 bytes (5 QWORDs on x64)

    @staticmethod
    def instruction_string_to_list(instruction_string: str) -> list:
        return [instruction.strip() for instruction in instruction_string.split(";") if instruction.strip()]

    def __init__(self, address: str, raw_string: str, module: str = None, arch: str = 'x86'):
        self._arch = arch.lower()
        self._address = f"0x{int(address, 16):x}"
        self._module = module
        self._raw = re.sub(r"\s{2,}", " ", raw_string.strip().lower())
        self._instructions = Gadget.instruction_string_to_list(instruction_string=self._raw)

    
    def uses_only_volatile_regs(self) -> bool:
        """Check if gadget only uses volatile (caller-saved) registers"""
        
        nonvolatile = get_nonvolatile_registers(self._arch)
        
        # Check if any non-volatile register appears in the gadget
        for nv_reg in nonvolatile:
            if re.search(rf'\b{nv_reg}\b', self._raw, re.IGNORECASE):
                return False
        
        return True

    def is_register_modified(self, reg: str, instructions: list) -> bool:
        """Check if register or its sub-registers are modified"""
        
        sub_registers = get_sub_registers(self._arch)
        registers_to_check = sub_registers.get(reg, [reg])

        for instr in instructions:
            instr_lower = instr.strip().lower()
            
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
            for modifier in SINGLE_OPERAND_MODIFIERS:
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

    def has_bad_op(self) -> bool:
        """Check if gadget contains bad operations"""
        
        # Check standard bad ops (without "call")
        for bad_op in self.BAD_OPS:
            if bad_op in self._raw:
                return True
        
        # Special handling for "call"
        if re.search(r"\bcall\b", self._raw, re.IGNORECASE):
            # Allow indirect calls to controlled registers
            controlled_calls = [
                r"\bcall\s+(rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r10|r11|r12|r13|r14|r15)\b",  # call rax
                r"\bcall\s+\[(rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r10|r11|r12|r13|r14|r15)",  # call [rax]
                r"\bcall\s+qword\s+ptr\s+\[(rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r10|r11|r12|r13|r14|r15)",  # call qword ptr [rax]
            ]
            
            # If it's a controlled indirect call, allow it
            if any(re.search(pattern, self._raw, re.IGNORECASE) for pattern in controlled_calls):
                return False  # Not a bad op

            return True   # Direct call or uncontrolled - bad op
        
        # Check for large retn values
        if match := re.search(r"retn 0x([0-9a-fA-F]+)", self._raw):
            if int(match.group(1), 16) > self.MAX_RETN:
                return True
        
        # Special case: iretq is only useful with swapgs
        if re.search(r"\biretq?\b", self._raw, re.IGNORECASE):
            if not re.search(r"swapgs\s*;\s*iretq?", self._raw, re.IGNORECASE):
                return True
        
        return False

    def has_bad_chars_in_address(self, bad_chars: list) -> bool:
        for byte in [self._address[i: i + 2] for i in range(2, len(self._address), 2)]:
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


class Gadgets:
    def __init__(self, file_paths: List[str], bad_chars: list = None, arch: str = 'x86'):
        self._bad_characters = bad_chars
        self._arch = arch.lower()
        self._unique_mode = False

        all_gadgets = []
        for file_path in file_paths:
            path = Path(file_path).resolve()
            if not path.is_file():
                print(f"[!] File {file_path} does not exist.")
                continue
            all_gadgets.extend(self._parse_file(path))

        # Store full list (all gadgets including bad ones)
        self._full_list = list(all_gadgets)
        
        # Filter bad gadgets
        bad_count = 0
        clean_gadgets = []
        for gadget in all_gadgets:
            if gadget.has_bad_op():
                bad_count += 1
            else:
                clean_gadgets.append(gadget)
        
        # Active list is what's used by iteration
        self._active_list = clean_gadgets
        
        print(f"\n[+] Total gadgets loaded: {len(self._full_list)}")
        print(f"|-> Clean gadgets (filtered): {len(self._active_list)}")
        print(f"|-> Bad gadgets (removed): {bad_count}")

    def use_full_catalog(self, enabled: bool):
        """Temporarily switch between clean and full catalog"""
        if enabled:
            self._active_list = self._full_list
        else:
            # Restore based on uniqueness mode
            if self._unique_mode:
                clean_gadgets = [g for g in self._full_list if not g.has_bad_op()]
                self._active_list = self._filter_unique(clean_gadgets)
            else:
                self._active_list = [g for g in self._full_list if not g.has_bad_op()]

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
        clean_gadgets = [g for g in self._full_list if not g.has_bad_op()]
        
        if enabled:
            self._active_list = self._filter_unique(clean_gadgets)  # ✅ Filter unique from CLEAN list
        else:
            self._active_list = clean_gadgets  # ✅ Use all CLEAN gadgets
        
        print(f"[+] Uniqueness mode {'enabled' if enabled else 'disabled'} ({len(self._active_list)} gadgets)")

    def _filter_unique(self, gadgets_list):
        """Filter for unique gadgets per module (same instruction, different addresses within same module)"""
        seen = {}
        for g in gadgets_list:
            # Key by both module and raw instruction
            key = (g.module, g.raw)
            if key not in seen:
                seen[key] = g
        return list(seen.values())

    def _parse_file(self, file_path: str) -> list:
        gadget_pattern = re.compile(r"^(0x[0-9a-fA-F]+):\s*(.+?)\s*(?:\(\d+\sfound\))?$", re.MULTILINE)

        start_time = time.time()
        
        with open(file_path, mode="r", encoding="utf-8") as file_obj:
            file_content = file_obj.read()
        
        bad_char_count = 0
        results = []

        for match in gadget_pattern.finditer(file_content):
            gadget = Gadget(
                address=match.group(1),
                raw_string=match.group(2).strip().lower(),
                module=file_path.stem,
                arch=self._arch,
            )
            if self._bad_characters and gadget.has_bad_chars_in_address(self._bad_characters):
                bad_char_count += 1
                continue
            results.append(gadget)
            
        elapsed_time = time.time() - start_time
        
        print(f"\n[+] {file_path.stem} parsed in {elapsed_time:.2f}s")
        print(f"|-> Total gadgets extracted: {len(results)}")
        print(f"|-> Gadgets containing bad characters: {bad_char_count}")
        return results

    def to_dict(self) -> dict:
        return {g.address: g.raw for g in self._active_list}

    @property
    def gadgets(self) -> list:
        return self._active_list

