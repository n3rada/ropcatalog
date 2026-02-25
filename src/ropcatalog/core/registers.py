# ropcatalog/core/registers.py

"""
Register definitions for x86 and x64 architectures.

This module centralizes all register-related constants and helper functions
for better maintainability and consistency across the codebase.
"""

from typing import Set, Dict, List

# ============================================================================
# X86 REGISTER DEFINITIONS
# ============================================================================

X86_REGISTERS: Set[str] = {
    # 32-bit general purpose
    "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
    
    # 16-bit general purpose
    "ax", "bx", "cx", "dx", "si", "di", "sp", "bp",
    
    # 8-bit general purpose
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"
}

# ============================================================================
# X64 ADDITIONAL REGISTERS (beyond x86)
# ============================================================================

X64_ADDITIONAL_REGISTERS: Set[str] = {
    # 64-bit general purpose
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    
    # Extended registers (64-bit)
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    
    # Extended registers (32-bit)
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    
    # Extended registers (16-bit)
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    
    # Extended registers (8-bit)
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    
    # Special 8-bit variants
    "sil", "dil"
}

# Complete x64 register set
X64_REGISTERS: Set[str] = X86_REGISTERS | X64_ADDITIONAL_REGISTERS

# ============================================================================
# VOLATILE (CALLER-SAVED) REGISTERS
# ============================================================================

VOLATILE_X86: Set[str] = {
    # 32-bit
    "eax", "ecx", "edx",
    
    # 16-bit
    "ax", "cx", "dx",
    
    # 8-bit
    "al", "cl", "dl", "ah", "ch", "dh"
}

VOLATILE_X64: Set[str] = VOLATILE_X86 | {
    # 64-bit
    "rax", "rcx", "rdx", "r8", "r9", "r10", "r11",
    
    # 32-bit
    "eax", "ecx", "edx", "r8d", "r9d", "r10d", "r11d",
    
    # 16-bit
    "ax", "cx", "dx", "r8w", "r9w", "r10w", "r11w",
    
    # 8-bit
    "al", "cl", "dl", "r8b", "r9b", "r10b", "r11b"
}

# ============================================================================
# NON-VOLATILE (CALLEE-SAVED) REGISTERS
# ============================================================================

NONVOLATILE_X86: Set[str] = {
    # 32-bit
    "ebx", "ebp", "esi", "edi", "esp",
    
    # 16-bit
    "bx", "bp", "si", "di", "sp"
}

NONVOLATILE_X64: Set[str] = NONVOLATILE_X86 | {
    # 64-bit
    "rbx", "rbp", "rsi", "rdi", "rsp", "r12", "r13", "r14", "r15",
    
    # 32-bit
    "ebx", "ebp", "esi", "edi", "esp", "r12d", "r13d", "r14d", "r15d",
    
    # 16-bit
    "bx", "bp", "si", "di", "sp", "r12w", "r13w", "r14w", "r15w",
    
    # 8-bit
    "bl", "bh", "bpl", "sil", "dil", "spl", "r12b", "r13b", "r14b", "r15b"
}

# ============================================================================
# SUB-REGISTER MAPPINGS
# ============================================================================

SUB_REGISTERS_X86: Dict[str, List[str]] = {
    "eax": ["eax", "ax", "al", "ah"],
    "ebx": ["ebx", "bx", "bl", "bh"],
    "ecx": ["ecx", "cx", "cl", "ch"],
    "edx": ["edx", "dx", "dl", "dh"],
    "esp": ["esp", "sp"],
    "ebp": ["ebp", "bp"],
    "esi": ["esi", "si"],
    "edi": ["edi", "di"],
}

SUB_REGISTERS_X64: Dict[str, List[str]] = {
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

# ============================================================================
# INSTRUCTION MODIFIERS
# ============================================================================

# Single-operand instructions that modify their operand
SINGLE_OPERAND_MODIFIERS: Set[str] = {
    "inc", "dec", "neg", "not", "push", "pop", "bswap"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_registers(arch: str) -> Set[str]:
    """
    Get all registers for the given architecture.
    
    Args:
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        Set of all valid register names for the architecture
        
    Examples:
        >>> get_registers('x64')
        {'rax', 'rbx', 'rcx', ..., 'r15b', 'sil', 'dil'}
    """
    arch = arch.lower()
    return X64_REGISTERS if arch == 'x64' else X86_REGISTERS


def get_volatile_registers(arch: str) -> Set[str]:
    """
    Get volatile (caller-saved) registers for the given architecture.
    
    Volatile registers do not need to be preserved across function calls.
    
    Args:
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        Set of volatile register names
        
    Examples:
        >>> get_volatile_registers('x64')
        {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11', ...}
    """
    arch = arch.lower()
    return VOLATILE_X64 if arch == 'x64' else VOLATILE_X86


def get_nonvolatile_registers(arch: str) -> Set[str]:
    """
    Get non-volatile (callee-saved) registers for the given architecture.
    
    Non-volatile registers must be preserved across function calls.
    
    Args:
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        Set of non-volatile register names
        
    Examples:
        >>> get_nonvolatile_registers('x64')
        {'rbx', 'rbp', 'rsi', 'rdi', 'rsp', 'r12', 'r13', 'r14', 'r15', ...}
    """
    arch = arch.lower()
    return NONVOLATILE_X64 if arch == 'x64' else NONVOLATILE_X86


def get_sub_registers(arch: str) -> Dict[str, List[str]]:
    """
    Get sub-register mappings for the given architecture.
    
    Returns a dictionary mapping each main register to its sub-registers.
    Used for detecting register modifications (e.g., modifying 'al' modifies 'rax').
    
    Args:
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        Dictionary mapping register names to lists of their sub-registers
        
    Examples:
        >>> get_sub_registers('x64')['rax']
        ['rax', 'eax', 'ax', 'al', 'ah']
    """
    arch = arch.lower()
    return SUB_REGISTERS_X64 if arch == 'x64' else SUB_REGISTERS_X86


def is_register(operand: str, arch: str = 'x86') -> bool:
    """
    Check if the operand is a valid register for the given architecture.
    
    Args:
        operand: The operand to check (e.g., 'rax', '0x123', 'ecx')
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        True if operand is a valid register, False otherwise
        
    Examples:
        >>> is_register('rax', 'x64')
        True
        >>> is_register('0x123', 'x64')
        False
        >>> is_register('eax', 'x86')
        True
        >>> is_register('r8', 'x86')
        False
    """
    operand = operand.lower().strip()
    
    # Quick check for immediates
    if operand.startswith("0x") or operand.isdigit():
        return False
    
    registers = get_registers(arch)
    return operand in registers


def is_volatile(reg: str, arch: str = 'x86') -> bool:
    """
    Check if a register is volatile (caller-saved).
    
    Args:
        reg: Register name to check
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        True if register is volatile, False otherwise
        
    Examples:
        >>> is_volatile('rax', 'x64')
        True
        >>> is_volatile('rbx', 'x64')
        False
    """
    reg = reg.lower().strip()
    volatile = get_volatile_registers(arch)
    return reg in volatile


def is_nonvolatile(reg: str, arch: str = 'x86') -> bool:
    """
    Check if a register is non-volatile (callee-saved).
    
    Args:
        reg: Register name to check
        arch: Architecture name ('x86' or 'x64')
        
    Returns:
        True if register is non-volatile, False otherwise
        
    Examples:
        >>> is_nonvolatile('rbx', 'x64')
        True
        >>> is_nonvolatile('rax', 'x64')
        False
    """
    reg = reg.lower().strip()
    nonvolatile = get_nonvolatile_registers(arch)
    return reg in nonvolatile
