"""
Strilight x86 Architecture Subsystem (strilight.arch.x86)
==========================================================
Concrete x86/x86-64 hardware definitions, instruction dispatchers,
EFLAGS/jcc condition analyzers, and register/memory state operations.
"""

from strilight.arch.x86.defs import (
    INSTRUCTION_META,
    REGISTER_HIERARCHY,
    PHYSICAL_REGS,
    REG_TO_BASE,
    BASE_TO_REGS,
    REGISTER_SIZES,
    REGISTER_MASKS,
    JCC_RELATIONAL_OPS,
    get_register_mask,
    get_instruction_type,
    get_flags_read,
    get_flags_written,
    is_full_register_clobber,
    get_base_register,
    get_subregisters,
    JUMP_FLAGS,
    SET_FLAGS,
    MODIFIES_ALL_FLAGS,
    MODIFIES_ZSO_ONLY,
)
from strilight.arch.x86.state_ops import (
    get_operand_list,
    get_op_key,
    get_dest_dset,
    set_dest_dset,
    get_src_dset,
    sign_extend_acc,
    sign_extend_hi,
)
from strilight.arch.x86.dispatcher import VSAInstructionDispatcher
from strilight.arch.x86.conditions import ConditionExtractor, StaticFlagTracker

__all__ = [
    "INSTRUCTION_META",
    "REGISTER_HIERARCHY",
    "PHYSICAL_REGS",
    "REG_TO_BASE",
    "BASE_TO_REGS",
    "REGISTER_SIZES",
    "REGISTER_MASKS",
    "JCC_RELATIONAL_OPS",
    "get_register_mask",
    "get_instruction_type",
    "get_flags_read",
    "get_flags_written",
    "is_full_register_clobber",
    "get_base_register",
    "get_subregisters",
    "JUMP_FLAGS",
    "SET_FLAGS",
    "MODIFIES_ALL_FLAGS",
    "MODIFIES_ZSO_ONLY",
    "get_operand_list",
    "get_op_key",
    "get_dest_dset",
    "set_dest_dset",
    "get_src_dset",
    "sign_extend_acc",
    "sign_extend_hi",
    "VSAInstructionDispatcher",
    "ConditionExtractor",
    "StaticFlagTracker",
]
