# ropcatalog/core/gadgets.py

# Built-in imports
import re
from pathlib import Path
import time
from typing import Union, List

def sort_key(gadget: 'Gadget') -> tuple:
    instr_count = len(gadget.instructions)
    # Penalize retn IMM to deprioritize large stack shifts
    if "retn 0x" in gadget.raw:
        return (instr_count + 0.5, int(re.search(r"retn 0x([0-9a-fA-F]+)", gadget.raw).group(1), 16))
    return (instr_count, 0)

def is_register(operand: str, arch: str = 'x86') -> bool:
    """
    Checks if the operand is a valid register for the given architecture.
    Returns True if operand is a register, False otherwise (e.g., for '0x...' immediates).
    """
    registers_x86 = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
        "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"
    }
    registers_x64 = registers_x86 | {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "sil", "dil"
    }
    registers = registers_x64 if arch == 'x64' else registers_x86
    operand = operand.lower().strip()
    if operand.startswith("0x"):
        return False
    return operand in registers


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
        """Check if gadget only modifies volatile (caller-saved) registers"""
        
        # Non-volatile (callee-saved) registers
        nonvolatile_x86 = {"ebx", "ebp", "esi", "edi", "esp", "bx", "bp", "si", "di", "sp"}
        nonvolatile_x64 = {"rbx", "rbp", "rsi", "rdi", "rsp", "r12", "r13", "r14", "r15",
                           "ebx", "ebp", "esi", "edi", "esp", "r12d", "r13d", "r14d", "r15d",
                           "bx", "bp", "si", "di", "sp", "r12w", "r13w", "r14w", "r15w",
                           "bl", "bh", "bpl", "sil", "dil", "spl", "r12b", "r13b", "r14b", "r15b"}
        
        nonvolatile = nonvolatile_x64 if self._arch == 'x64' else nonvolatile_x86
        
        # Check each instruction (except ret)
        for instr in self._instructions[:-1]:  # Exclude 'ret'
            if "," in instr:
                # Check destination register
                dest = instr.split(",")[0].strip().split()[-1]  # Get last word before comma
                if dest.lower() in nonvolatile:
                    return False
            elif instr.startswith("pop "):
                # Check what's being popped
                reg = instr.split()[1].strip()
                if reg.lower() in nonvolatile:
                    return False
        
        return True

   def is_register_modified(self, reg: str, instructions: list) -> bool:
        """Check if register or its sub-registers are modified"""
        
        sub_registers_x86 = {
            "eax": ["eax", "ax", "al", "ah"],
            "ebx": ["ebx", "bx", "bl", "bh"],
            "ecx": ["ecx", "cx", "cl", "ch"],
            "edx": ["edx", "dx", "dl", "dh"],
            "esp": ["esp", "sp"],
            "ebp": ["ebp", "bp"],
            "esi": ["esi", "si"],
            "edi": ["edi", "di"],
        }
    
        sub_registers_x64 = {
            "rax": ["rax", "eax", "ax", "al", "ah"],
            "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
            "rcx": ["rcx", "ecx", "cx", "cl", "ch"],
            "rdx": ["rdx", "edx", "dx", "dl", "dh"],
            "rsp": ["rsp", "esp", "sp"],
            "rbp": ["rbp", "ebp", "bp"],
            "rsi": ["rsi", "esi", "si", "sil"],
            "rdi": ["rdi", "edi", "di", "dil"],
            "r8": ["r8", "r8d", "r8w", "r8b"],
            "r9": ["r9", "r9d", "r9w", "r9b"],
            "r10": ["r10", "r10d", "r10w", "r10b"],
            "r11": ["r11", "r11d", "r11w", "r11b"],
            "r12": ["r12", "r12d", "r12w", "r12b"],
            "r13": ["r13", "r13d", "r13w", "r13b"],
            "r14": ["r14", "r14d", "r14w", "r14b"],
            "r15": ["r15", "r15d", "r15w", "r15b"],
        }
    
        sub_registers = sub_registers_x64 if self._arch == 'x64' else sub_registers_x86
        registers_to_check = sub_registers.get(reg, [reg])
    
        # Instructions that modify their operand (single-operand instructions)
        single_operand_modifiers = ["inc", "dec", "neg", "not", "push", "pop", "bswap"]
    
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
                    if reg_check in instr_lower:
                        return True
            
            # Check for single-operand modifying instructions (inc, dec, neg, etc.)
            for modifier in single_operand_modifiers:
                if instr_lower.startswith(modifier + " "):
                    # Extract the operand
                    parts = instr_lower.split()
                    if len(parts) >= 2:
                        operand = parts[1].strip()
                        if operand in registers_to_check:
                            return True
            
            # Check for comma-separated instructions (dest is before comma)
            if "," in instr_lower:
                dest = instr_lower.split(",")[0].strip().split()[-1]  # Last word before comma
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

