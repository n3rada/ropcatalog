# ropcatalog/core/formatters.py

# Built-in imports
import re

class GadgetFormatter:
    def format(self, gadget, with_base_address=False) -> str:
        raise NotImplementedError


class CppFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        # Use module name as-is, just append "Base"
        base = f"{gadget.module}Base + " if with_base_address else ""
        return f"*rop++ = {base}{gadget.address}; // {gadget.raw} [{gadget.module}]"


class PythonFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        # Use correct pack format based on architecture
        pack_format = "<Q" if gadget.arch == 'x64' else "<L"
        
        header = f'rop += pack("{pack_format}", '
        if with_base_address:
            header += f"ba__{gadget.module} + "
        header += gadget.address
        return f"{header}) # {gadget.raw} [{gadget.module}]"


class JavaScriptFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        def to_camel_case(name: str) -> str:
            return ''.join(word.capitalize() for word in re.split(r'\W|_', name))
        
        camel_module = to_camel_case(gadget.module)
        base = f"g{camel_module}Base + " if with_base_address else ""
        
        # JavaScript always uses 8-byte pointers for writePtr
        # (handles both x86 and x64 uniformly at JS level)
        return f"writePtr(ropBuffer + ropIndex * 8, {base}{gadget.address}); ropIndex++; // {gadget.raw} [{gadget.module}]"


class PlainFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        return str(gadget)
        
