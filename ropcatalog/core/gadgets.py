# Built-in imports
import re
from pathlib import Path
from typing import Union, List


def is_register_modified(reg: str, instructions: list) -> bool:
    """
    Checks if a register or its sub-registers are modified in the given instructions.

    Args:
        reg (str): The register to check (e.g., "eax").
        instructions (list): A list of instruction strings.

    Returns:
        bool: True if the register or any sub-registers are modified, False otherwise.
    """
    # Map each main register to its sub-registers
    sub_registers = {
        "eax": ["eax", "ax", "al", "ah"],
        "ebx": ["ebx", "bx", "bl", "bh"],
        "ecx": ["ecx", "cx", "cl", "ch"],
        "edx": ["edx", "dx", "dl", "dh"],
        "esp": ["esp", "sp"],
        "ebp": ["ebp", "bp"],
        "esi": ["esi", "si"],
        "edi": ["edi", "di"],
    }

    # Get the list of relevant registers to check
    registers_to_check = sub_registers.get(reg, [reg])

    # Check if any of the main or sub-registers are modified in the instructions
    for instr in instructions:
        for reg_check in registers_to_check:
            if "," in instr:
                if reg_check in instr.split(",")[0]:
                    return True
            else:
                if f"pop {reg_check}" in instr:
                    return True
    return False


class Gadget:

    # In ROP chains, the goal is to execute a sequence of gadgets that are small,
    # predictable and controlled via the stack.
    # Any instruction that changes the control flow, stack pointer
    # or depends on unpredictable conditions
    # is considered bad because it introduces instability into the exploit.
    BAD_OPS = {
        "int3",
        "call",
        "leave",
        "loop",
        "loopne",
        "jmp",
        "jz",
        "je",
        "jnz",
        "jne",
        "ja",
        "jae",
        "jna",
        "jnae",
        "jb",
        "jbe",
        "jnb",
        "jnbe",
    }

    MAX_RETN = 0x28  # 10 DWORDs (10 * 4 bytes = 40 bytes)

    @staticmethod
    def instruction_string_to_list(instruction_string: str) -> list:
        return [
            instruction.strip()
            for instruction in instruction_string.split(";")
            if instruction.strip()
        ]

    def __init__(self, address: str, raw_string: str, module: str = None):

        self._address = f"0x{int(address, 16):x}"

        # Normalize spaces in the raw instruction string
        normalized_raw = re.sub(r"\s{2,}", " ", raw_string.strip().lower())
        self._raw = normalized_raw

        self._instructions = Gadget.instruction_string_to_list(
            instruction_string=self._raw
        )
        self._module = module

    def has_bad_op(self) -> bool:
        """
        Checks if any bad operations are present in the gadget.
        """
        return any(bad_op in self._raw for bad_op in self.BAD_OPS)

    def has_big_retn(self) -> bool:
        """
        Checks if the gadget ends with a large `retn 0x...` value.
        """
        if match := re.search(r"retn 0x([0-9a-fA-F]+)", self._raw):
            retn_value = int(match.group(1), 16)
            return retn_value > self.MAX_RETN
        return False

    def has_bad_chars_in_address(self, bad_chars: list) -> bool:
        """
        Checks if the address of the gadget contains any bad characters.

        Args:
            bad_chars (list): A list of bad character hex strings (e.g., ['00', '0a', '0d']).

        Returns:
            bool: True if any bad character is found in the address, False otherwise.
        """

        for byte in [self._address[i : i + 2] for i in range(2, len(self._address), 2)]:
            if byte in bad_chars:
                return True

        return False

    def verify_push_coherence(self, target_register: str) -> bool:
        """
        Checks if the given assembly instruction string contains a valid sequence where `src` is pushed
        and subsequently popped into any destination register.
        """

        # Stack to simulate push/pop operations
        pushed = []

        for instr in self._instructions:
            # Split and strip the instruction into the command and register
            parts = instr.split()
            if len(parts) != 2:
                continue  # Skip malformed instructions

            cmd, reg = parts[0].strip(), parts[1].strip()

            if cmd == "push":
                pushed.append(reg)  # Push the register onto the simulated stack
            elif cmd == "pop" and pushed:
                tmp = pushed.pop()  # Pop the last pushed register

                # Check if the popped register matches the source we're interested in
                if tmp == target_register:
                    return True  # Found a valid match

        return False

    def exact_match(self, search_term: str) -> bool:
        return Gadget.instruction_string_to_list(search_term) == self._instructions

    def partial_match(self, search_term: str) -> bool:
        return all(
            search_op in self._raw
            for search_op in Gadget.instruction_string_to_list(search_term)
        )

    def regex(self, patterns: Union[str, list[str]]) -> bool:
        if isinstance(patterns, str):
            patterns = [patterns]

        # Iterate over the list of patterns and search for a match
        for regex_pattern in patterns:
            if re.search(regex_pattern, self._raw, re.IGNORECASE):
                return True
        return False

    def pattern_match(self, patterns: Union[str, list[str]]) -> list[re.Match]:
        if isinstance(patterns, str):
            patterns = [patterns]

        matches = []
        # Iterate over the list of patterns and search for all matches
        for regex_pattern in patterns:
            matches.extend(re.finditer(regex_pattern, self._raw, re.IGNORECASE))

        return matches

    def pythonic_string(self, with_base_address: bool = False) -> str:
        header = 'rop += pack("<L", '

        if with_base_address:
            header += f"ba__{self._module} + "

        header += self._address

        return header + f") # {self._raw} [{self._module}]"

    def __str__(self):
        return f"{self._address} # {self._raw} [{self._module}]"

    def __repr__(self):
        return f"Gadget({self._address}, {self._raw}, {self._instructions})"

    # Properties
    @property
    def raw(self) -> str:
        return self._raw

    @property
    def address(self) -> str:
        return self._address

    @property
    def instructions(self) -> list:
        return self._instructions


class Gadgets:

    def __init__(self, file_paths: List[str], bad_chars: list = None):
        self._gadgets = []

        self._bad_characters = bad_chars

        for file_path in file_paths:
            path = Path(file_path).resolve()
            if not path.is_file():
                print(f"[!] File {file_path} does not exist.")
                continue

            self._gadgets.extend(self._parse_file(path))

        print(f"[+] Total of {len(self)} gadgets loaded")

    def __iter__(self):
        return iter(self._gadgets)

    def __len__(self):
        return len(self._gadgets)

    def add_gadget(self, gadget: Gadget) -> None:
        """
        Adds a Gadget object to the collection.
        """
        if isinstance(gadget, Gadget):
            self._gadgets.append(gadget)
        else:
            raise TypeError("Only Gadget objects can be added.")

    def filter_unique(self) -> None:
        """
        Filters the gadget list to only retain unique gadgets based on the raw instruction sequence.
        """
        unique_gadgets = {}
        for gadget in self._gadgets:
            if gadget.raw not in unique_gadgets:
                unique_gadgets[gadget.raw] = gadget

        self._gadgets = list(unique_gadgets.values())
        print(
            f"[+] Filtered to {len(self._gadgets)} unique gadgets based on instructions."
        )

    def _parse_file(self, file_path: str) -> list:
        print(f"[*] Parsing {file_path.name}, looking for usable gadgets")
        # Regex pattern to match the address and the list of operations
        gadget_pattern = re.compile(
            r"^(0x[0-9a-fA-F]+):\s*(.+?)\s*(?:\(\d+\sfound\))?$", re.MULTILINE
        )

        with open(file_path, mode="r", encoding="utf-8") as file_obj:
            file_content = file_obj.read()

        bad_char_count = 0

        results = []

        # Iterate over all matches in the file content and yield each gadget
        for match in gadget_pattern.finditer(file_content):
            gadget = Gadget(
                address=match.group(1),
                raw_string=match.group(2).strip().lower(),
                module=file_path.stem,
            )

            # If any bad character is present in the address
            if self._bad_characters is not None and gadget.has_bad_chars_in_address(
                self._bad_characters
            ):
                bad_char_count += 1
                continue

            results.append(gadget)

        print(f"\n[{file_path.stem}] Parsing completed:")
        print(f"[+] Total gadgets extracted: {len(results)}")
        print(f"[+] {bad_char_count} gadgets contained bad characters")

        return results

    def to_dict(self) -> dict:
        """
        Transforms the collection of Gadget objects to a dictionary {address: raw}.
        """
        return {gadget.address: gadget.raw for gadget in self._gadgets}

    # Properties
    @property
    def gadgets(self) -> list:
        return self._gadgets
