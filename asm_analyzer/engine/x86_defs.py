from typing import List, Dict, Any, Set

INSTRUCTION_META: Dict[str, Dict[str, Any]] = {
    # Data Transfer & Extension
    'mov': {'type': 'data_transfer'},
    'movzx': {'type': 'data_transfer'},
    'movsx': {'type': 'data_transfer'},
    'movsxd': {'type': 'data_transfer'},
    'lea': {'type': 'data_transfer'},
    'xchg': {'type': 'data_transfer'},
    'lock xchg': {'type': 'data_transfer'},
    'cbw': {'type': 'data_transfer'},
    'cwde': {'type': 'data_transfer'},
    'cdqe': {'type': 'data_transfer'},
    'cwd': {'type': 'data_transfer'},
    'cdq': {'type': 'data_transfer'},
    'cqo': {'type': 'data_transfer'},
    'push': {'type': 'stack'},
    'pop': {'type': 'stack'},
    
    # Control Flow
    'call': {'type': 'call'},
    'ret': {'type': 'ret'},
    
    # Arithmetic and Logic
    'add': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'sub': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'xor': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'and': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'or': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'cmp': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'test': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'inc': {'type': 'math', 'flags_written': ['flag_zf', 'flag_sf', 'flag_of']}, # inc/dec don't write CF
    'dec': {'type': 'math', 'flags_written': ['flag_zf', 'flag_sf', 'flag_of']},
    'shl': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'shr': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'sar': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'mul': {'type': 'math', 'flags_written': ['flag_cf', 'flag_of']},
    'imul': {'type': 'math', 'flags_written': ['flag_cf', 'flag_of']},
    'cmpxchg': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    'lock cmpxchg': {'type': 'math', 'flags_written': ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']},
    
    # Jumps (Unconditional and Conditional)
    'jmp': {'type': 'jump'},
    'je': {'type': 'jcc', 'flags_read': ['flag_zf']},
    'jz': {'type': 'jcc', 'flags_read': ['flag_zf']},
    'jne': {'type': 'jcc', 'flags_read': ['flag_zf']},
    'jnz': {'type': 'jcc', 'flags_read': ['flag_zf']},
    'ja': {'type': 'jcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'jnbe': {'type': 'jcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'jae': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jnb': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jnc': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jb': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jc': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jnae': {'type': 'jcc', 'flags_read': ['flag_cf']},
    'jbe': {'type': 'jcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'jna': {'type': 'jcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'jg': {'type': 'jcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'jnle': {'type': 'jcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'jge': {'type': 'jcc', 'flags_read': ['flag_sf', 'flag_of']},
    'jnl': {'type': 'jcc', 'flags_read': ['flag_sf', 'flag_of']},
    'jl': {'type': 'jcc', 'flags_read': ['flag_sf', 'flag_of']},
    'jnge': {'type': 'jcc', 'flags_read': ['flag_sf', 'flag_of']},
    'jle': {'type': 'jcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'jng': {'type': 'jcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'js': {'type': 'jcc', 'flags_read': ['flag_sf']},
    'jns': {'type': 'jcc', 'flags_read': ['flag_sf']},
    'jo': {'type': 'jcc', 'flags_read': ['flag_of']},
    'jno': {'type': 'jcc', 'flags_read': ['flag_of']},
    
    # SetCC
    'sete': {'type': 'setcc', 'flags_read': ['flag_zf']},
    'setz': {'type': 'setcc', 'flags_read': ['flag_zf']},
    'setne': {'type': 'setcc', 'flags_read': ['flag_zf']},
    'setnz': {'type': 'setcc', 'flags_read': ['flag_zf']},
    'seta': {'type': 'setcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'setnbe': {'type': 'setcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'setae': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setnb': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setnc': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setb': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setc': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setnae': {'type': 'setcc', 'flags_read': ['flag_cf']},
    'setbe': {'type': 'setcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'setna': {'type': 'setcc', 'flags_read': ['flag_cf', 'flag_zf']},
    'setg': {'type': 'setcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'setnle': {'type': 'setcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'setge': {'type': 'setcc', 'flags_read': ['flag_sf', 'flag_of']},
    'setnl': {'type': 'setcc', 'flags_read': ['flag_sf', 'flag_of']},
    'setl': {'type': 'setcc', 'flags_read': ['flag_sf', 'flag_of']},
    'setnge': {'type': 'setcc', 'flags_read': ['flag_sf', 'flag_of']},
    'setle': {'type': 'setcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'setng': {'type': 'setcc', 'flags_read': ['flag_zf', 'flag_sf', 'flag_of']},
    'sets': {'type': 'setcc', 'flags_read': ['flag_sf']},
    'setns': {'type': 'setcc', 'flags_read': ['flag_sf']},
    'seto': {'type': 'setcc', 'flags_read': ['flag_of']},
    'setno': {'type': 'setcc', 'flags_read': ['flag_of']},
}

def get_instruction_type(mnemonic: str) -> str:
    """Returns the type tag of the instruction (e.g. 'jcc', 'math', 'data_transfer')"""
    meta = INSTRUCTION_META.get(mnemonic)
    return meta['type'] if meta else 'unknown'

def get_flags_read(mnemonic: str) -> List[str]:
    """Returns a list of flags read by the instruction"""
    meta = INSTRUCTION_META.get(mnemonic)
    return meta.get('flags_read', []) if meta else []

def get_flags_written(mnemonic: str) -> List[str]:
    """Returns a list of flags modified by the instruction"""
    meta = INSTRUCTION_META.get(mnemonic)
    return meta.get('flags_written', []) if meta else []

# ==========================================
# Centralized x86_64 Register Definitions
# ==========================================

REGISTER_HIERARCHY: Dict[str, Set[str]] = {
    "rax": {"rax", "eax", "ax", "al", "ah"},
    "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
    "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
    "rdx": {"rdx", "edx", "dx", "dl", "dh"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "rsp": {"rsp", "esp", "sp", "spl"},
    "r8": {"r8", "r8d", "r8w", "r8b"},
    "r9": {"r9", "r9d", "r9w", "r9b"},
    "r10": {"r10", "r10d", "r10w", "r10b"},
    "r11": {"r11", "r11d", "r11w", "r11b"},
    "r12": {"r12", "r12d", "r12w", "r12b"},
    "r13": {"r13", "r13d", "r13w", "r13b"},
    "r14": {"r14", "r14d", "r14w", "r14b"},
    "r15": {"r15", "r15d", "r15w", "r15b"},
}

REG_TO_BASE: Dict[str, str] = {}
BASE_TO_REGS: Dict[str, Set[str]] = {}

for _base, _subs in REGISTER_HIERARCHY.items():
    BASE_TO_REGS[_base] = set(_subs)
    for _sub in _subs:
        REG_TO_BASE[_sub] = _base

PHYSICAL_REGS: List[str] = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

REGISTER_SIZES: Dict[str, int] = {
    # 64-bit
    "rax": 8, "rbx": 8, "rcx": 8, "rdx": 8, "rsi": 8, "rdi": 8, "rbp": 8, "rsp": 8,
    "r8": 8, "r9": 8, "r10": 8, "r11": 8, "r12": 8, "r13": 8, "r14": 8, "r15": 8,
    # 32-bit
    "eax": 4, "ebx": 4, "ecx": 4, "edx": 4, "esi": 4, "edi": 4, "ebp": 4, "esp": 4,
    "r8d": 4, "r9d": 4, "r10d": 4, "r11d": 4, "r12d": 4, "r13d": 4, "r14d": 4, "r15d": 4,
    # 16-bit
    "ax": 2, "bx": 2, "cx": 2, "dx": 2, "si": 2, "di": 2, "bp": 2, "sp": 2,
    "r8w": 2, "r9w": 2, "r10w": 2, "r11w": 2, "r12w": 2, "r13w": 2, "r14w": 2, "r15w": 2,
    # 8-bit
    "al": 1, "bl": 1, "cl": 1, "dl": 1, "ah": 1, "bh": 1, "ch": 1, "dh": 1,
    "sil": 1, "dil": 1, "bpl": 1, "spl": 1,
    "r8b": 1, "r9b": 1, "r10b": 1, "r11b": 1, "r12b": 1, "r13b": 1, "r14b": 1, "r15b": 1,
}

REGISTER_MASKS: Dict[str, int] = {
    # 64-bit
    "rax": 0xFFFFFFFFFFFFFFFF, "rbx": 0xFFFFFFFFFFFFFFFF, "rcx": 0xFFFFFFFFFFFFFFFF, "rdx": 0xFFFFFFFFFFFFFFFF,
    "rsi": 0xFFFFFFFFFFFFFFFF, "rdi": 0xFFFFFFFFFFFFFFFF, "rbp": 0xFFFFFFFFFFFFFFFF, "rsp": 0xFFFFFFFFFFFFFFFF,
    "r8": 0xFFFFFFFFFFFFFFFF, "r9": 0xFFFFFFFFFFFFFFFF, "r10": 0xFFFFFFFFFFFFFFFF, "r11": 0xFFFFFFFFFFFFFFFF,
    "r12": 0xFFFFFFFFFFFFFFFF, "r13": 0xFFFFFFFFFFFFFFFF, "r14": 0xFFFFFFFFFFFFFFFF, "r15": 0xFFFFFFFFFFFFFFFF,
    # 32-bit (Lower 32 bits)
    "eax": 0xFFFFFFFF, "ebx": 0xFFFFFFFF, "ecx": 0xFFFFFFFF, "edx": 0xFFFFFFFF,
    "esi": 0xFFFFFFFF, "edi": 0xFFFFFFFF, "ebp": 0xFFFFFFFF, "esp": 0xFFFFFFFF,
    "r8d": 0xFFFFFFFF, "r9d": 0xFFFFFFFF, "r10d": 0xFFFFFFFF, "r11d": 0xFFFFFFFF,
    "r12d": 0xFFFFFFFF, "r13d": 0xFFFFFFFF, "r14d": 0xFFFFFFFF, "r15d": 0xFFFFFFFF,
    # 16-bit (Lower 16 bits)
    "ax": 0xFFFF, "bx": 0xFFFF, "cx": 0xFFFF, "dx": 0xFFFF,
    "si": 0xFFFF, "di": 0xFFFF, "bp": 0xFFFF, "sp": 0xFFFF,
    "r8w": 0xFFFF, "r9w": 0xFFFF, "r10w": 0xFFFF, "r11w": 0xFFFF,
    "r12w": 0xFFFF, "r13w": 0xFFFF, "r14w": 0xFFFF, "r15w": 0xFFFF,
    # 8-bit low (Lower 8 bits)
    "al": 0xFF, "bl": 0xFF, "cl": 0xFF, "dl": 0xFF,
    "sil": 0xFF, "dil": 0xFF, "bpl": 0xFF, "spl": 0xFF,
    "r8b": 0xFF, "r9b": 0xFF, "r10b": 0xFF, "r11b": 0xFF,
    "r12b": 0xFF, "r13b": 0xFF, "r14b": 0xFF, "r15b": 0xFF,
    # 8-bit high (Bits 8..15)
    "ah": 0xFF00, "bh": 0xFF00, "ch": 0xFF00, "dh": 0xFF00,
}

def get_register_mask(reg: str) -> int:
    """Returns the 64-bit bitmask for any register or subregister (e.g. 'al' -> 0xFF, 'ah' -> 0xFF00)."""
    return REGISTER_MASKS.get(reg.lower(), 0xFFFFFFFFFFFFFFFF)

def is_full_register_clobber(reg: str) -> bool:
    """In x86-64, writes to >= 32-bit registers (e.g. 'eax', 'rax') clobber the full 64-bit base register."""
    return REGISTER_SIZES.get(reg.lower(), 8) >= 4

def get_base_register(reg: str) -> str:
    """Returns 64-bit base register name for any subregister (e.g. 'eax' -> 'rax')"""
    return REG_TO_BASE.get(reg, reg)

def get_subregisters(reg: str) -> Set[str]:
    """Returns set of all aliases/subregisters for a given register"""
    base = REG_TO_BASE.get(reg, reg)
    return BASE_TO_REGS.get(base, {reg})

# ==========================================
# Centralized Flag Maps for Tracker
# ==========================================

JUMP_FLAGS: Dict[str, List[str]] = {
    m: meta['flags_read'] for m, meta in INSTRUCTION_META.items() if meta.get('type') == 'jcc'
}

SET_FLAGS: Dict[str, List[str]] = {
    m: meta['flags_read'] for m, meta in INSTRUCTION_META.items() if meta.get('type') == 'setcc'
}

MODIFIES_ALL_FLAGS: Set[str] = {
    m for m, meta in INSTRUCTION_META.items() if len(meta.get('flags_written', [])) >= 4
}

MODIFIES_ZSO_ONLY: Set[str] = {
    m for m, meta in INSTRUCTION_META.items() if meta.get('flags_written') == ['flag_zf', 'flag_sf', 'flag_of']
}


