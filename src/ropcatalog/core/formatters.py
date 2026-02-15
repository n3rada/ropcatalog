import re

class GadgetFormatter:
    def format(self, gadget, with_base_address=False) -> str:
        raise NotImplementedError


class PythonFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        header = 'rop += pack("<L", '
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
        return f"writePtr(ropBuffer + ropIndex * 8, {base}{gadget.address}); ropIndex++; // {gadget.raw} [{gadget.module}]"

class PlainFormatter(GadgetFormatter):
    def format(self, gadget, with_base_address=False) -> str:
        return str(gadget)
