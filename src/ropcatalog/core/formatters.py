# ropcatalog/core/formatters.py

# Built-in imports
import re
from .gadgets import Gadget

class GadgetFormatter:
    def format(self, gadget: Gadget, with_base_address: bool = False) -> str:
        """Format one gadget for the selected output language.

        Args:
            gadget: Gadget to render.
            with_base_address: Whether formatted addresses use module base expressions.

        Returns:
            Formatter-specific source line for the gadget.

        Raises:
            NotImplementedError: Always, because subclasses provide concrete formatting.
        """
        raise NotImplementedError


class CppFormatter(GadgetFormatter):
    def format(self, gadget: Gadget, with_base_address: bool = False) -> str:
        """Format a gadget as a C++ ROP-buffer assignment.

        Args:
            gadget: Gadget to render.
            with_base_address: Whether formatted addresses use module base expressions.

        Returns:
            C++ pointer write that appends the gadget to a ROP chain.
        """
        # Use module name as-is, just append "Base"
        base = f"{gadget.module}Base + " if with_base_address else ""
        return f"*rop++ = {base}{gadget.address}; // {gadget.raw} [{gadget.module}]"


class PythonFormatter(GadgetFormatter):
    def format(self, gadget: Gadget, with_base_address: bool = False) -> str:
        """Format a gadget as a Python ``struct.pack`` expression.

        Args:
            gadget: Gadget to render.
            with_base_address: Whether formatted addresses use module base expressions.

        Returns:
            Architecture-width ``struct.pack`` expression for the gadget.
        """
        # Use correct pack format based on architecture
        pack_format = "<Q" if gadget.arch == 'x64' else "<L"
        
        header = f'rop += pack("{pack_format}", '
        if with_base_address:
            header += f"ba__{gadget.module} + "
        header += gadget.address
        return f"{header}) # {gadget.raw} [{gadget.module}]"


class JavaScriptFormatter(GadgetFormatter):
    def format(self, gadget: Gadget, with_base_address: bool = False) -> str:
        """Format a gadget as a JavaScript ROP-buffer write.

        Args:
            gadget: Gadget to render.
            with_base_address: Whether formatted addresses use module base expressions.

        Returns:
            JavaScript ``writePtr`` statement for the gadget.
        """

        def to_camel_case(name: str) -> str:
            """Convert a module name into a JavaScript identifier fragment.

            Args:
                name: Module name to convert.

            Returns:
                Identifier-safe title-cased module fragment.
            """
            return ''.join(word.capitalize() for word in re.split(r'\W|_', name))
        
        camel_module = to_camel_case(gadget.module)
        base = f"g{camel_module}Base + " if with_base_address else ""
        
        # JavaScript always uses 8-byte pointers for writePtr
        # (handles both x86 and x64 uniformly at JS level)
        return f"writePtr(ropBuffer + ropIndex * 8, {base}{gadget.address}); ropIndex++; // {gadget.raw} [{gadget.module}]"


class PlainFormatter(GadgetFormatter):
    def format(self, gadget: Gadget, with_base_address: bool = False) -> str:
        """Format a gadget using its concise plain representation.

        Args:
            gadget: Gadget to render.
            with_base_address: Whether formatted addresses use module base expressions.

        Returns:
            Concise address, instructions, and module representation.
        """
        return str(gadget)
        
