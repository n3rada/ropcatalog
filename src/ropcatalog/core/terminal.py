# ropcatalog/core/terminal.py

# Built-in imports
from typing import TYPE_CHECKING

import os
import sys
import re

# Third party library imports
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import ThreadedHistory, InMemoryHistory
from prompt_toolkit.cursor_shapes import CursorShape
from prompt_toolkit.completion import WordCompleter

# Local library imports
from . import gadgets
from . import formatters


class Terminal:
    """
    Manages console commands and dispatches them.
    """

    def __init__(self,
        full_catalog: "gadgets.Gadgets",
        formatter: "formatters.GadgetFormatter" = None,
        with_base_address: bool=False
    ):
        self._gadgets = full_catalog
        self._formatter = formatter
        self._with_base_address = with_base_address

        self._commands = {
            "exit": self.exit_command,
            "clear": self.clear_command,
            "list": self.list_gadgets,
            "uniq": self.toggle_uniqueness,
            "style": self.change_style,
            "help": self.show_help,
            "?": self.exact_search,
            "/": self.partial_search,
            "copy": self.copy_register,
            "copyto": self.copy_to_register,
            "save": self.save_register,
            "saveto": self.save_to_register,
            "inc": self.increment_register,
            "dec": self.decrement_register,
            "read": self.dereference_register,  # Alias for deref
            "deref": self.dereference_register,
            "write": self.write_primitive,
            "memoff": self.memory_offset_search,
            ".": self.regex_search,
            "swap": self.swap_register,
            "zero": self.zero,
            "ppr": self.find_ppr,
            "jump": self.find_jump_gadgets,
            "iretq": self.find_iretq,
            "call": self.indirect_call,
            "push": self.push_register,
            "pop": self.pop_to_register,
            "pivot": self.stack_pivot,
        }

    def change_style(self, style_name: str = None) -> None:
        """Change output format style (e.g., style python, style cpp)"""
        
        from . import formatters  # Import here to avoid circular dependency
        
        style_map = {
            "plain": formatters.PlainFormatter,
            "python": formatters.PythonFormatter,
            "cpp": formatters.CppFormatter,
            "js": formatters.JavaScriptFormatter,
        }
        
        if not style_name:
            # Show current style
            current = type(self._formatter).__name__.replace('Formatter', '').lower()
            print(f"[i] Current style: {current}")
            print(f"[i] Available styles: {', '.join(style_map.keys())}")
            return
        
        style_name = style_name.lower()
        
        if style_name not in style_map:
            print(f"[!] Unknown style '{style_name}'")
            print(f"[i] Available styles: {', '.join(style_map.keys())}")
            return
        
        self._formatter = style_map[style_name]()
        print(f"[+] Output style changed to: {style_name}")
    
    def toggle_uniqueness(self, mode: str = None):
        """Toggle uniqueness filtering (uniq on/off)"""
        if not mode:
            # When called without arguments, toggle the current state
            new_state = not self._gadgets._unique_mode
            self._gadgets.set_uniqueness(new_state)
            print(f"[+] Uniqueness mode toggled to: {'on' if new_state else 'off'}")
            return

        if mode.lower() == "on":
            self._gadgets.set_uniqueness(True)
        elif mode.lower() == "off":
            self._gadgets.set_uniqueness(False)
        else:
            print("[!] Usage: uniq [on|off]")
            print("\tNo argument toggles current state")

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
            print("[i] Filtering disabled")
            filtering = False

        results = self._commands[cmd](args) or []

        # Check if exit command was called
        if cmd == "exit" and results is True:
            raise SystemExit(0)

        if filtering and isinstance(results, list):
            results = [gadget for gadget in results if not gadget.has_bad_op()]

        return results if isinstance(results, list) else []

    # Command methods

    def show_help(self, fake_arg=None) -> None:
        """Show available commands"""
        
        # Group commands by category
        categories = {
            "General": {
                "help": "Show this help message",
                "exit": "Exit ropcatalog",
                "clear": "Clear the terminal screen",
                "list": "List all gadgets",
                "uniq": "Toggle uniqueness filtering (uniq on/off)",
                "style": "Change output format (style python/cpp/js/plain)"
            },
            "Search": {
                "?": "Exact search (e.g., ? pop eax ; ret)",
                "/": "Partial search (e.g., / pop)",
                ".": "Regex search (e.g., . mov.*rax)",
                "memoff": "Memory offset search (e.g., memoff rbx+0x20)",
            },
            "Register Operations": {
                "copy": "Copy register to another (e.g., copy rax)",
                "copyto": "Copy into register (e.g., copyto r9)",
                "save": "Save register without modification (e.g., save rbx)",
                "saveto": "Save into register without modification (e.g., saveto rcx)",
                "swap": "Swap registers (e.g., swap eax)",
                "zero": "Zero a register (e.g., zero rax)",
                "inc": "Increment register (e.g., inc eax)",
                "dec": "Decrement register (e.g., dec edx)",
            },
            "Memory Operations": {
                "read": "Read from memory (e.g., read rbx finds mov rax, [rbx])",
                "write": "Write to memory (e.g., write rcx finds mov [rax], rcx)",
                "deref": "Alias for 'read'",
            },
            "Stack Operations": {
                "push": "Push register to stack (e.g., push rax)",
                "pop": "Pop from stack to register (e.g., pop rbx)",
                "ppr": "Find pop-pop-ret sequences",
                "pivot": "Stack pivot gadgets (pivot all/reg/imm)",
            },
            "Control Flow": {
                "jump": "Jump gadgets (e.g., jump esp)",
                "call": "Indirect call gadgets (e.g., call rax)",
                "iretq": "Kernel->user transition (swapgs ; iretq)",
            },
        }
        
        for category, commands in categories.items():
            print(f"\n{category}:")
            print("-" * 70)
            for cmd, desc in commands.items():
                print(f"  {cmd:<10} {desc}")
        
        print("\n" + "="*70)
        print("Modifiers:")
        print("  /n         Disable bad operation filtering (e.g., jump esp /n)")
        print("="*70 + "\n")

    def exit_command(self, fake_arg=None) -> bool:
        """Exit"""
        return True

    def clear_command(self, fake_arg=None):
        """Clear the terminal"""
        os.system("cls" if os.name == "nt" else "clear")

    def list_gadgets(self, fake_arg=None) -> list:
        """List all gadgets"""
        return self._gadgets

    def exact_search(self, instructions: str) -> list:
        """Exact search for gadgets (e.g., ? pop eax ; ret)"""
        print(f"[*] Exact search of '{instructions}'")
        return [g for g in self._gadgets if g.exact_match(instructions)]

    def partial_search(self, instructions: str) -> list:
        """Partial search for gadgets (e.g., / pop)"""

        print(f"[*] Partial search of '{instructions}'")
        return [g for g in self._gadgets if g.partial_match(instructions)]
    

    def find_iretq(self, fake_arg=None) -> list:
        """Find kernel->user transition gadgets (swapgs ; iretq)"""
        print("[*] Finding kernel->user transition gadgets (swapgs ; iretq)")
        
        patterns = [
            r"swapgs\s*;\s*iretq",
            r"swapgs\s*;\s*iret",
        ]
        
        return [g for g in self._gadgets if any(re.search(p, g.raw, re.IGNORECASE) for p in patterns)]

    def copy_register(self, reg: str) -> list:
        """This method finds gadgets that copy the value of a register (e.g., eax) to another register with modifcation of copied register allowed."""

        results = []

        print(f"[*] Finding gadgets that copy {reg} register into another one.")

        patterns = [
            rf"mov (\w+), {reg}",  # mov <reg>, reg
            rf"lea (\w+), \[{reg}.+?\]",
        ]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    # Check if the register is modified in the remaining instructions
                    if not gadget.is_register_modified(
                        matched_reg, remaining_instructions
                    ):
                        results.append(gadget)

            # Now, handle the 'push <reg>' case
            if f"push {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                results.append(gadget)

        return results

    def stack_pivot(self, args: str = None) -> list:
        """Find stack pivot gadgets (e.g., 'pivot' for all, 'pivot reg' for register-based, 'pivot imm' for immediate values)"""
        
        results = []
        mode = args.strip().lower() if args else "all"
        
        if mode not in ["all", "reg", "imm"]:
            print("[!] Usage: pivot [all|reg|imm]")
            print("\tall - Find all stack pivot gadgets (default)")
            print("\treg - Find register-based pivots (mov esp, <reg>)")
            print("\timm - Find immediate value pivots (mov esp, 0x########)")
            return []
        
        print(f"[*] Finding stack pivot gadgets (mode: {mode})")
        
        for gadget in self._gadgets:
            arch = gadget.arch
            
            # Clean split - strip whitespace AND trailing semicolons
            instructions = [i.strip().rstrip(';').strip() for i in gadget.raw.split(" ; ") if i.strip()]
            
            # Only accept gadgets ending in ret/retn/iretq
            last_instr = instructions[-1].strip().lower()
            if not (last_instr == 'ret' or last_instr.startswith('retn') or last_instr == 'iretq'):
                continue
            
            # Register-based pivots
            if mode in ["all", "reg"]:
                stack_regs = ["rsp", "esp"] if arch == 'x64' else ["esp"]
                
                for stack_reg in stack_regs:
                    reg_patterns = [
                        rf"mov {stack_reg}, (\w+)",
                        rf"xchg {stack_reg}, (\w+)",
                    ]
                    
                    for i, instr in enumerate(instructions[:-1]):
                        for pattern in reg_patterns:
                            if match := re.search(pattern, instr.strip(), re.IGNORECASE):
                                source_reg = match.group(1)
                                
                                if gadgets.is_register(source_reg, arch=arch):
                                    remaining = instructions[i+1:-1]
                                    
                                    clobbered = any(
                                        re.search(rf"\bmov (?:rsp|esp),", instr, re.IGNORECASE) or
                                        re.search(rf"\bxchg (?:rsp|esp),", instr, re.IGNORECASE) or
                                        re.search(rf"\blea (?:rsp|esp),", instr, re.IGNORECASE)
                                        for instr in remaining
                                    )
                                    
                                    if not clobbered:
                                        results.append(gadget)
                                        break
            
            # Immediate value pivots
            if mode in ["all", "imm"]:
                imm_patterns = []
                if arch == 'x64':
                    imm_patterns = [
                        rf"mov rsp, (0x[0-9a-fA-F]+)",
                        rf"mov esp, (0x[0-9a-fA-F]+)",
                    ]
                else:
                    imm_patterns = [rf"mov esp, (0x[0-9a-fA-F]+)"]
                
                for i, instr in enumerate(instructions[:-1]):
                    for pattern in imm_patterns:
                        if match := re.search(pattern, instr.strip(), re.IGNORECASE):
                            imm_str = match.group(1)
                            imm_value = int(imm_str, 16)
                            
                            is_reasonable = False
                            if arch == 'x64':
                                is_reasonable = (imm_value <= 0xFFFFFFFF)
                            else:
                                is_reasonable = (imm_value >= 0x00010000)
                            
                            if is_reasonable:
                                remaining = instructions[i+1:-1]
                                
                                clobbered = any(
                                    re.search(rf"\bmov (?:rsp|esp),", instr, re.IGNORECASE) or
                                    re.search(rf"\bxchg (?:rsp|esp),", instr, re.IGNORECASE) or
                                    re.search(rf"\blea (?:rsp|esp),", instr, re.IGNORECASE)
                                    for instr in remaining
                                )
                                
                                if not clobbered:
                                    results.append(gadget)
                                    break
        
        return results
 
    def copy_to_register(self, reg: str) -> list:
        """Find gadgets that copy into the given register (e.g., r9)"""

        results = []

        print(f"[*] Finding gadgets that copy into {reg}")

        patterns = [
            rf"mov {reg}, (\w+)",
            rf"lea {reg}, \[(\w+).+?\]",
        ]

        for gadget in self._gadgets:
            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)
                    remaining_instructions = gadget.instructions[matched_index + 1:]

                    # Ensure the destination is not clobbered afterward
                    if not gadget.is_register_modified(reg, remaining_instructions):
                        results.append(gadget)

            # Support stack transfer too
            if f"pop {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                matched_index = gadget.instructions.index(f"pop {reg}")
                remaining_instructions = gadget.instructions[matched_index + 1:]
                if not gadget.is_register_modified(reg, remaining_instructions):
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
            rf"lea (\w+), \[{reg}.+?\]",
        ]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)

                    matched_reg = match.group(1)

                    # Ensure the matched_reg is a register
                    if not gadgets.is_register(matched_reg, arch=gadget.arch):
                        continue

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    # Check if the register is modified in the remaining instructions
                    if not gadget.is_register_modified(
                        matched_reg, remaining_instructions
                    ) and not gadget.is_register_modified(reg, remaining_instructions):
                        results.append(gadget)

            # Now, handle the 'push <reg>' case
            if f"push {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                matched_index = gadget.instructions.index(f"push {reg}")
                remaining_instructions = gadget.instructions[matched_index + 1 :]
                if not gadget.is_register_modified(reg, remaining_instructions):
                    results.append(gadget)

        return results
    
    def save_to_register(self, reg: str) -> list:
        """Find gadgets that save into the given register without modifying either register afterward."""

        results = []

        print(f"[*] Finding gadgets that save into {reg} without later modification")

        patterns = [
            rf"mov {reg}, (\w+)",
            rf"lea {reg}, \[(\w+).+?\]",
        ]

        for gadget in self._gadgets:
            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    source_reg = match.group(1)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)
                    remaining_instructions = gadget.instructions[matched_index + 1:]

                    if not gadget.is_register_modified(reg, remaining_instructions) and \
                    not gadget.is_register_modified(source_reg, remaining_instructions):
                        results.append(gadget)

            if f"pop {reg}" in gadget.raw and gadget.verify_push_coherence(reg):
                matched_index = gadget.instructions.index(f"pop {reg}")
                remaining_instructions = gadget.instructions[matched_index + 1:]
                if not gadget.is_register_modified(reg, remaining_instructions):
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

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    # Check if the register is modified in the remaining instructions
                    if not gadget.is_register_modified(
                        matched_reg, remaining_instructions
                    ):
                        results.append(gadget)

        return results

    def push_register(self, reg: str) -> list:
        """This method finds gadgets that push a register onto the stack without any other pop following."""

        results = []

        print(f"[*] Finding gadgets that push {reg} onto the stack")

        patterns = [rf"push ({reg})"]

        for gadget in self._gadgets:

            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    if "pop" not in " ; ".join(remaining_instructions):
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
            rf"add {reg}, 0x[0-9a-fA-F]+",
            rf"sub {reg}, -0x[0-9a-fA-F]+",
            rf"inc {reg}",
            rf"lea {reg}, \[{reg}\+0x[0-9a-fA-F]+\]",
        ]
        return [g for g in self._gadgets if g.regex(patterns)]

    def decrement_register(self, reg: str) -> list:
        """Find gadgets that decrement a register (e.g., dec eax)"""
        print(f"[*] Finding gadgets that decrement {reg}")
        patterns = [
            rf"sub {reg}, 0x[0-9a-fA-F]+",
            rf"add {reg}, -0x[0-9a-fA-F]+",
            rf"dec {reg}",
            rf"lea {reg}, \[{reg}\-0x[0-9a-fA-F]+\]",
        ]
        return [g for g in self._gadgets if g.regex(patterns)]

    def dereference_register(self, reg: str) -> list:
        """Read from memory (e.g., read rbx finds mov rax, [rbx])"""
        
        print(f"[*] Finding gadgets that read from memory pointed by {reg}")

        results = []

        patterns = [
            rf"(?:mov|xchg) (\w+), (?:dword )?\[{reg}\]",
            rf"xchg (?:dword )?\[{reg}\], (\w+)",
        ]

        for gadget in self._gadgets:
            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    if not gadget.is_register_modified(
                        matched_reg, remaining_instructions
                    ):
                        results.append(gadget)

            # Now, handle the 'push [<reg>]' case
            if f"push [{reg}]" in gadget.raw and gadget.verify_push_coherence(reg):
                results.append(gadget)

        return results

    def swap_register(self, reg: str) -> list:
        """Find gadgets that swap given register with any other register (e.g., xchg eax, <reg>)"""

        print(f"[*] Finding gadgets that swap {reg} with any other register")

        results = []

        patterns = [rf"xchg (\w+), {reg}", rf"xchg {reg}, (\w+)"]

        for gadget in self._gadgets:
            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    matched_reg = match.group(1)

                    if matched_instruction not in gadget.instructions:
                        continue

                    matched_index = gadget.instructions.index(matched_instruction)

                    # Take only the instructions AFTER the matched one
                    remaining_instructions = gadget.instructions[matched_index + 1 :]

                    # Check if the register is modified in the remaining instructions

                    if not gadget.is_register_modified(
                        matched_reg, remaining_instructions
                    ):
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

    def write_primitive(self, reg: str = None) -> list:
        """Write register to memory (e.g., write rbx finds mov [rax], rbx)"""
        
        if not reg:
            print("[!] Usage: write <source_register>")
            return []
        
        print(f"[*] Finding gadgets that write {reg} to memory")
        
        results = []
        patterns = [
            rf"mov (?:qword ptr )?\[(\w+)\], {reg}",
            rf"mov (?:dword ptr )?\[(\w+)\], {reg}",
            rf"mov (?:qword ptr )?\[(\w+)\s*[+\-]\s*0x[0-9a-fA-F]+\], {reg}",
        ]
        
        for gadget in self._gadgets:
            if matches := gadget.pattern_match(patterns):
                for match in matches:
                    matched_instruction = match.group(0)
                    ptr_reg = match.group(1)
                    
                    if matched_instruction not in gadget.instructions:
                        continue
                    
                    matched_index = gadget.instructions.index(matched_instruction)
                    remaining_instructions = gadget.instructions[matched_index + 1:]
                    
                    if not gadget.is_register_modified(ptr_reg, remaining_instructions):
                        results.append(gadget)
                        break
        
        return results

    def indirect_call(self, reg: str) -> list:
        """Indirect call gadgets (e.g., call rax, call [rbx+0x10])"""
        
        print(f"[*] Finding indirect call gadgets for {reg}")
        
        patterns = [
            rf"call {reg}",
            rf"call (?:qword ptr )?\[{reg}\]",
            rf"call (?:qword ptr )?\[{reg}\s*[+\-]\s*0x[0-9a-fA-F]+\]",
        ]
        
        return [g for g in self._gadgets if g.regex(patterns)]
    
    def memory_offset_search(self, arg: str):
        """Search for dereferences with register+offset (e.g., memoff rbx+0x20, or just memoff rbx to match any offset)"""

        if not arg:
            print("[!] Usage: memoff <reg> [+/- offset (optional)]")
            return []

        reg = arg.strip()
        pattern = None

        if '+' in reg or '-' in reg:
            sep = '+' if '+' in reg else '-'
            try:
                base_reg, offset = reg.split(sep, maxsplit=1)
                base_reg = base_reg.strip()
                offset = offset.strip()
                pattern = rf"mov.*\[\s*{base_reg}\s*{re.escape(sep)}\s*{offset}\s*\],.*"
            except ValueError:
                print("[!] Failed to parse register and offset. Use format: reg+offset or reg-offset")
                return []
        else:
            # Match any offset off that register: [reg + ...] or [reg - ...]
            pattern = rf"mov.*\[\s*{reg}\s*[\+\-]\s*.*\],.*"

        return [g for g in self._gadgets if re.search(pattern, g.raw, re.IGNORECASE)]


    def regex_search(self, pattern: str) -> str:
        """Search for gadgets using a regular expression pattern (e.g., re mov eax, .*)"""
        print(f"[*] Searching with regex '{pattern}'")

        return [g for g in self._gadgets if re.search(pattern, g.raw, re.IGNORECASE)]


    def start(self) -> int:
        session = PromptSession(
            cursor=CursorShape.BLINKING_BEAM,
            multiline=False,
            enable_history_search=True,
            wrap_lines=True,
            auto_suggest=AutoSuggestFromHistory(),
            history=ThreadedHistory(InMemoryHistory()),
            complete_while_typing=True,
            completer=WordCompleter(list(self._commands.keys()), ignore_case=True),
        )

        ctrl_c_count = 0

        while True:
            try:
                command = session.prompt("[ropcatalog]# ").strip() or "help"

                results = self.execute(command)

                if results:
                    results = sorted(results, key=gadgets.sort_key, reverse=True)
                    for gadget in results:
                        print(self._formatter.format(gadget, self._with_base_address))

                    print(f"---- {len(results)} gadget(s)")
            except KeyboardInterrupt:
                # Control-C pressed - check if buffer has text first
                if session.app.current_buffer.text:
                    continue

                ctrl_c_count += 1
                if ctrl_c_count >= 2:
                    print("[+] Exiting on double Ctrl+C.")
                    return 130
                else:
                    print("[i] Press Ctrl+C again to exit, or type 'exit'.")
                    continue
            except SystemExit:
                # Exit command was called
                return 0
            except re.error:
                print("[!] Wrongly typed command")
