import re


def verify_bytes(gadget_list):
    records = []
    if not gadget_list:
        return {"method": "capstone", "status": "not_requested", "executes_target_bytes": False, "gadgets": []}
    try:
        import capstone
    except ImportError:
        return {
            "method": "capstone",
            "status": "unavailable",
            "executes_target_bytes": False,
            "failure": "install capstone to re-disassemble gadget bytes",
            "gadgets": [],
        }

    complete = True
    for gadget in gadget_list:
        if gadget.bytes_hex is None:
            complete = False
            records.append({"gadget_id": gadget.identifier, "status": "unavailable", "failure": "opcode bytes absent"})
            continue
        try:
            code = bytes.fromhex(gadget.bytes_hex)
        except ValueError:
            complete = False
            records.append({"gadget_id": gadget.identifier, "status": "invalid_bytes"})
            continue
        mode = capstone.CS_MODE_64 if gadget.arch == "x64" else capstone.CS_MODE_32
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        decoded = [f"{instruction.mnemonic} {instruction.op_str}".strip() for instruction in disassembler.disasm(code, 0)]
        matches = [_normalize(item) for item in decoded] == [_normalize(item) for item in gadget.instructions]
        complete &= matches
        records.append({
            "gadget_id": gadget.identifier,
            "status": "verified" if matches else "mismatch",
            "decoded": decoded,
        })
    return {
        "method": "capstone",
        "status": "verified" if complete else "incomplete",
        "executes_target_bytes": False,
        "gadgets": records,
    }


def _normalize(instruction):
    value = instruction.lower().replace(" ptr ", " ")
    value = re.sub(r"\s*,\s*", ",", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value



def emulate_chain(gadget_list, chain, desired, scratch):
    try:
        import unicorn
        from unicorn import x86_const
    except ImportError:
        return {
            "method": "unicorn",
            "status": "unavailable",
            "executes_target_bytes": False,
            "failure": "install unicorn to execute resolved gadget bytes",
        }
    if not gadget_list or any(gadget.bytes_hex is None for gadget in gadget_list):
        return {"method": "unicorn", "status": "unavailable", "executes_target_bytes": False, "failure": "opcode bytes absent"}
    gadget_words = {word.get("gadget_id"): word for word in chain["words"] if word["kind"] == "gadget"}
    if any(not gadget_words.get(gadget.identifier, {}).get("resolved") for gadget in gadget_list):
        return {"method": "unicorn", "status": "unavailable", "executes_target_bytes": False, "failure": "gadget addresses unresolved"}
    try:
        expected = {register: int(value, 0) for register, value in desired.items()}
        scratch_values = [int(value, 0) for value in scratch]
    except (TypeError, ValueError):
        return {"method": "unicorn", "status": "unavailable", "executes_target_bytes": False, "failure": "symbolic state unresolved"}

    arch64 = gadget_list[0].arch == "x64"
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64 if arch64 else unicorn.UC_MODE_32)
    page_size = 0x1000
    mapped = set()

    def map_page(address):
        page = address & ~(page_size - 1)
        if page not in mapped:
            emulator.mem_map(page, page_size)
            mapped.add(page)

    try:
        for gadget in gadget_list:
            address = int(gadget_words[gadget.identifier]["value"], 0)
            code = bytes.fromhex(gadget.bytes_hex)
            for page_address in range(address & ~(page_size - 1), (address + len(code) + page_size - 1) & ~(page_size - 1), page_size):
                map_page(page_address)
            emulator.mem_write(address, code)
        for address in scratch_values:
            map_page(address)
        stack_base = 0x700000000000 if arch64 else 0x70000000
        stack_size = 0x10000
        emulator.mem_map(stack_base, stack_size)
        stop_address = stack_base - page_size
        emulator.mem_map(stop_address, page_size)
        emulator.mem_write(stop_address, b"\xcc")
        runtime_words = []
        for word in chain["words"]:
            if word.get("resolved"):
                runtime_words.append(int(word["value"], 0))
            elif word["kind"] in {"continuation", "return", "padding", "shadow"}:
                runtime_words.append(stop_address if word["kind"] in {"continuation", "return"} else 0x4141414141414141)
            else:
                return {"method": "unicorn", "status": "unavailable", "executes_target_bytes": False, "failure": "symbolic chain word unresolved"}
        stack = b"".join(value.to_bytes(chain["word_size"], "little") for value in runtime_words[1:])
        emulator.mem_write(stack_base, stack)
        instruction_pointer = x86_const.UC_X86_REG_RIP if arch64 else x86_const.UC_X86_REG_EIP
        stack_pointer = x86_const.UC_X86_REG_RSP if arch64 else x86_const.UC_X86_REG_ESP
        emulator.reg_write(instruction_pointer, runtime_words[0])
        emulator.reg_write(stack_pointer, stack_base)
        executed = 0

        def on_code(uc, address, size, user_data):
            nonlocal executed
            executed += 1
            if address == stop_address:
                uc.emu_stop()

        emulator.hook_add(unicorn.UC_HOOK_CODE, on_code)
        emulator.emu_start(runtime_words[0], 0, count=max(64, len(runtime_words) * 16))
        register_values = {}
        for register, expected_value in expected.items():
            constant = getattr(x86_const, f"UC_X86_REG_{register.upper()}")
            register_values[register] = f"0x{emulator.reg_read(constant):x}"
        failures = [register for register, expected_value in expected.items() if int(register_values[register], 0) != expected_value]
        return {
            "method": "unicorn",
            "status": "verified" if not failures else "mismatch",
            "executes_target_bytes": True,
            "instructions": executed,
            "registers": register_values,
            "failures": failures,
        }
    except (ValueError, unicorn.UcError) as error:
        return {
            "method": "unicorn",
            "status": "failed",
            "executes_target_bytes": True,
            "failure": str(error),
        }
