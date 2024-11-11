# Built-in imports
import os
import sys
import re
import argparse
from pathlib import Path

# Third party library imports
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import ThreadedHistory, InMemoryHistory
from prompt_toolkit.cursor_shapes import CursorShape

# Local library imports
from rp_catalog.core import gadgets
from rp_catalog.core import utils


class Console:
    """
    Manages console commands and dispatches them.
    """

    def __init__(self, catalog: gadgets.Gadgets):
        self._gadgets = catalog
        self._commands = {
            "exit": self.exit_command,
            "clear": self.clear_command,
            "list": self.list_gadgets,
            "help": self.show_help,
            "?": self.exact_search,
            "/": self.partial_search,
            "copy": self.copy_register,
            "save": self.save_register,
            "inc": self.increment_register,
            "dec": self.decrement_register,
            "deref": self.dereference_register,
            "re": self.regex_search,
            "swap": self.swap_register,
            "zero": self.zero,
            "ppr": self.find_ppr,
            "jump": self.find_jump_gadgets,
            "pop": self.pop_to_register,
        }

    def execute(self, command_input: str) -> list:
        """
        Executes the command based on the input.
        """
        command_parts = command_input.split(maxsplit=1)
        cmd = command_parts[0].lower()
        args = command_parts[1].strip().lower() if len(command_parts) > 1 else None

        results = []

        if not cmd in self._commands:
            print(
                f"[!] Unrecognized command '{cmd}'. Type 'help' for available commands."
            )
            return []

        filtering = True

        if args is not None and args.endswith(" /n"):
            args = args.replace(" /n", "")
            filtering = False

        results = self._commands[cmd](args) or []

        if filtering:
            results = [gadget for gadget in results if not gadget.has_bad_op()]

        return results

    # Command methods

    def exit_command(self, fake_arg=None):
        """Exit"""
        print("[+] Exiting.")
        sys.exit(1)

    def clear_command(self, fake_arg=None):
        """Clear the terminal"""
        os.system("cls" if os.name == "nt" else "clear")

    def list_gadgets(self, fake_arg=None) -> list:
        """List all gadgets"""
        return self._gadgets

    def show_help(self, fake_arg=None) -> None:
        print("Available commands:")
        for cmd, func in self._commands.items():
            print(f"  {cmd:<5} - {func.__doc__}")

    def exact_search(self, instructions: str) -> list:
        """Exact search for gadgets (e.g., ? pop eax ; ret)"""
        print(f"[*] Exact search of '{instructions}'")
        return [g for g in self._gadgets if g.exact_match(instructions)]

    def partial_search(self, instructions: str) -> list:
        """Partial search for gadgets (e.g., / pop)"""

        print(f"[*] Partial search of '{instructions}'")
        return [g for g in self._gadgets if g.partial_match(instructions)]

    def copy_register(self, reg: str) -> list:
        """This method finds gadgets that copy the value of a register (e.g., eax) to another register with modifcation of copied register allowed."""

        results = []

        print(f"[*] Finding gadgets that copy {reg} register into another one.")

        patterns = [
            rf"mov (\w+), {reg}",  # mov <reg>, reg
        ]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)  # Destination register from the regex

                    # Ensure the matched instruction exists in the gadget's instructions
                    if matched_instruction in gadget.instructions:
                        matched_index = gadget.instructions.index(matched_instruction)

                        # Take only the instructions AFTER the matched one
                        remaining_instructions = gadget.instructions[
                            matched_index + 1 :
                        ]

                        # Check if the register is modified in the remaining instructions
                        if not gadgets.is_register_modified(
                            matched_reg, remaining_instructions
                        ):
                            results.append(gadget)

            # Now, handle the 'push <reg>' case
            if f"push {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                results.append(gadget)

        return results

    def save_register(self, reg: str) -> list:
        """This method finds gadgets that copy the value of a register (e.g., eax) to another register without modifying either register afterward."""

        results = []

        print(
            f"[*] Finding gadgets that save {reg} register into another without modifications"
        )

        patterns = [
            rf"mov (\w+), {reg}",
        ]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)  # Destination register from the regex

                    # Ensure the matched instruction exists in the gadget's instructions
                    if matched_instruction in gadget.instructions:
                        matched_index = gadget.instructions.index(matched_instruction)

                        # Take only the instructions AFTER the matched one
                        remaining_instructions = gadget.instructions[
                            matched_index + 1 :
                        ]

                        # Check if the register is modified in the remaining instructions
                        if not gadgets.is_register_modified(
                            matched_reg, remaining_instructions
                        ) and not gadgets.is_register_modified(
                            reg, remaining_instructions
                        ):
                            results.append(gadget)

            # Now, handle the 'push <reg>' case
            if f"push {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                matched_index = gadget.instructions.index(f"push {reg}")
                remaining_instructions = gadget.instructions[matched_index + 1 :]
                if not gadgets.is_register_modified(reg, remaining_instructions):
                    results.append(gadget)

        return results

    def pop_to_register(self, reg: str) -> list:
        """This method finds gadgets that load a value from the stack into a specified register, typically through the pop instruction."""

        results = []

        print(f"[*] Finding gadgets that pop onto {reg}")

        patterns = [rf"pop ({reg})", rf"mov ({reg}), [esp]"]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)  # Destination register from the regex

                    # Ensure the matched instruction exists in the gadget's instructions
                    if matched_instruction in gadget.instructions:
                        matched_index = gadget.instructions.index(matched_instruction)

                        # Take only the instructions AFTER the matched one
                        remaining_instructions = gadget.instructions[
                            matched_index + 1 :
                        ]

                        # Check if the register is modified in the remaining instructions
                        if not gadgets.is_register_modified(
                            matched_reg, remaining_instructions
                        ):
                            results.append(gadget)

        return results

    def find_ppr(self, fake_arg=None) -> list:
        """Find gadgets with pop-pop-ret sequences (e.g., pop eax ; pop ebx ; ret)"""
        print("[*] Finding gadgets with pop-pop-ret sequences")

        # Define the pattern for pop-pop-ret gadgets
        pattern = r"pop \w+ ; pop \w+ ; ret"

        # Filter gadgets based on the regex pattern
        return [g for g in self._gadgets if re.search(pattern, g.raw, re.IGNORECASE)]

    def increment_register(self, reg: str) -> list:
        """Find gadgets that increment a register (e.g., inc eax)"""
        print(f"[*] Finding gadgets that increment {reg}")
        patterns = [
            rf"add {reg}, 0x[1-9a-fA-F]+",
            rf"sub {reg}, -0x[1-9a-fA-F]+",
            rf"inc {reg}",
            rf"lea {reg}, \[{reg}\+0x[1-9a-fA-F]+\]",
        ]
        return [g for g in self._gadgets if g.regex(patterns)]

    def decrement_register(self, reg: str) -> list:
        """Find gadgets that decrement a register (e.g., dec eax)"""
        print(f"[*] Finding gadgets that decrement {reg}")
        patterns = [
            rf"sub {reg}, 0x[1-9a-fA-F]+",
            rf"add {reg}, -0x[1-9a-fA-F]+",
            rf"dec {reg}",
            rf"lea {reg}, \[{reg}\-0x[1-9a-fA-F]+\]",
        ]
        return [g for g in self._gadgets if g.regex(patterns)]

    def dereference_register(self, reg: str) -> list:
        """Find gadgets that dereference a register (e.g., mov eax, [eax])"""
        results = []
        print(f"[*] Finding gadgets that deref {reg} register")

        for gadget in self._gadgets:
            if matches := gadget.pattern_match(
                rf"(mov|xchg) (\w+), (?:dword )?\[{reg}\]"
            ):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)

                    if matched_instruction:
                        matched_index = gadget.instructions.index(matched_instruction)

                        # Take only the instructions AFTER the matched one
                        remaining_instructions = gadget.instructions[
                            matched_index + 1 :
                        ]

                        # Check if the register is modified in the remaining instructions

                        if not gadgets.is_register_modified(
                            matched_reg, remaining_instructions
                        ):
                            results.append(gadget)

            # Now, handle the 'push [<reg>]' case
            if f"push [{reg}]" in gadget.raw and gadget.verify_push_coherence(reg):
                results.append(gadget)

        return results

    def find_jump_gadgets(self, reg: str) -> list:
        """Find jump-related gadgets (e.g., jmp esp, call esp, jmp [esp+0x10], etc.)"""
        print(f"[*] Finding jump-related gadgets to {reg}")

        # Define the pattern for jump gadgets
        patterns = [
            rf"jmp {reg}",
            rf"jmp dword \[{reg}.*\]",
            rf"call {reg}",
            rf"call dword \[{reg}.*\]",
        ]

        # Filter gadgets based on the regex pattern
        jump_gadgets = [
            g
            for g in self._gadgets
            if any(re.search(p, g.raw, re.IGNORECASE) for p in patterns)
        ]

        return jump_gadgets

    def swap_register(self, reg: str) -> list:
        """Find gadgets that swap given register with any other register (e.g., xchg eax, <reg>)"""

        print(f"[*] Finding gadgets that swap {reg} with any other register")

        # Look for `xchg` instructions
        pattern = rf"xchg {reg}, \w+|xchg \w+, {reg}"
        return [g for g in self._gadgets if g.regex(pattern)]

    def zero(self, reg: str) -> list:
        """Find gadgets that zero the given register"""

        print(f"[*] Find gadgets that zero {reg}")

        patterns = [
            rf"xor {reg}, {reg}",
            rf"sub {reg}, {reg}",
            rf"lea [{reg}], 0 ;",
            rf"mov {reg}, 0 ;",
            rf"and {reg}, 0 ;",
        ]

        return [g for g in self._gadgets if g.regex(patterns)]

    def regex_search(self, pattern: str) -> str:
        """Search for gadgets using a regular expression pattern (e.g., re mov eax, .*)"""
        print(f"[*] Searching with regex '{pattern}'")

        return [g for g in self._gadgets if re.search(pattern, g.raw, re.IGNORECASE)]

    def start(
        self, pythonic_string: bool = False, with_base_address: bool = False
    ) -> None:
        session = PromptSession(
            cursor=CursorShape.BLINKING_BEAM,
            multiline=False,
            enable_history_search=True,
            wrap_lines=True,
            auto_suggest=AutoSuggestFromHistory(),
            history=ThreadedHistory(InMemoryHistory()),
            complete_while_typing=True,
        )
        print()
        while True:
            try:
                command = session.prompt("[rp_catalog]# ").strip()
                results = self.execute(command)

                if results:
                    results = sorted(results, key=lambda x: len(x.raw), reverse=True)
                    for gadget in results:
                        if pythonic_string:
                            print(gadget.pythonic_string(with_base_address))
                        else:
                            print(gadget)

                    print(f"---- {len(results)} gadget(s)")
            except KeyboardInterrupt:
                print("[i] Keyboard interruption received. Not exiting.")
            except re.error:
                print("[!] Wrongly typed command")


def run() -> None:
    parser = argparse.ArgumentParser(
        prog="catalog", description="r++ gadget parser for specific instructions."
    )

    parser.add_argument(
        "paths",
        nargs="+",
        help="Paths to one or more ROP files generated by r++. Directory also accepted.",
    )

    parser.add_argument(
        "-b",
        "--bad-characters",
        type=str,
        default="",
        required=False,
        help="A string of characters to exclude in the format '\\x00\\x0a\\x0d'.",
    )

    parser.add_argument(
        "-u",
        "--unique",
        action="store_true",
        help="Filter for unique gadgets by their raw instruction sequences.",
    )

    parser.add_argument(
        "-p",
        "--python",
        action="store_true",
        help="Display in a convenient way for python3 copy/paste.",
    )

    parser.add_argument(
        "-o",
        "--offset",
        action="store_true",
        help="The file contains only the offset (e.g., ALSR case).",
    )

    args = parser.parse_args()

    bad_chars = None
    if args.bad_characters:
        bad_chars = utils.format_bad_chars(args.bad_characters)

    print(f"[+] Bad characters: {bad_chars}")

    # Collect files from both file and directory paths
    file_paths = []
    for path_str in args.paths:
        path = Path(path_str).resolve()

        if path.is_dir():
            # Add all files in the directory
            file_paths.extend([file for file in path.iterdir() if file.is_file()])
        elif path.is_file():
            file_paths.append(path)
        else:
            print(f"[!] Path '{path}' is not a valid file or directory.")

    catalog = gadgets.Gadgets(file_paths=file_paths, bad_chars=bad_chars)

    if len(catalog) == 0:
        print("[!] No gadgets available, try another module")
        sys.exit(1)

    # Filter for unique gadgets if -u flag is set
    if args.unique:
        catalog.filter_unique()

    console = Console(catalog)

    console.start(pythonic_string=args.python, with_base_address=args.offset)
