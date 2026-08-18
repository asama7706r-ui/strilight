from typing import List, Dict, Any

INSTRUCTION_META: Dict[str, Dict[str, Any]] = {
    # Data Transfer
    'mov': {'type': 'data_transfer'},
    'movzx': {'type': 'data_transfer'},
    'movsx': {'type': 'data_transfer'},
    'movsxd': {'type': 'data_transfer'},
    'lea': {'type': 'data_transfer'},
    'push': {'type': 'stack'},
    'pop': {'type': 'stack'},
    
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
