import copy
from typing import Optional, List, Dict, Any
from strilight.engine.abstract_state import AbstractState
from strilight.pruning.interval import Interval, DisjointIntervalSet
from strilight.engine.vsa.state_ops import (
    get_operand_list,
    get_op_key,
    get_dest_dset,
    set_dest_dset,
    get_src_dset,
    sign_extend_acc,
    sign_extend_hi,
)


class VSAInstructionDispatcher:
    """
    Instruction Dispatcher for Value Set Analysis (VSA).
    Maps x86 abstract instruction semantics to interval transfer functions.
    """

    @staticmethod
    def eval_binary_op(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int, op_func: Any) -> None:
        if len(operands) < 2:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        dest_dset = get_dest_dset(state, dest)
        if not dest_dset:
            return
        src_dset = get_src_dset(state, record, operands[1])
        if not src_dset:
            return

        new_dset = DisjointIntervalSet(k_limit=8)
        for d_int in dest_dset.intervals:
            for s_int in src_dset.intervals:
                res = op_func(d_int, s_int)
                if isinstance(res, DisjointIntervalSet):
                    for r in res.intervals:
                        new_dset.add(r)
                elif res is not None:
                    new_dset.add(res)
        set_dest_dset(state, dest, new_dset, size)

    @staticmethod
    def eval_unary_op(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int, is_inc: bool) -> None:
        if len(operands) < 1:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        dest_dset = get_dest_dset(state, dest)
        if not dest_dset:
            return

        step_int = Interval(1, 1)
        new_dset = DisjointIntervalSet(k_limit=8)
        for d_int in dest_dset.intervals:
            res = d_int.add(step_int) if is_inc else d_int.sub(step_int)
            for r in res.intervals:
                new_dset.add(r)
        set_dest_dset(state, dest, new_dset, size)

    @staticmethod
    def eval_neg_op(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int) -> None:
        if len(operands) < 1:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        dest_dset = get_dest_dset(state, dest)
        if not dest_dset:
            return
        zero_int = Interval(0, 0)
        new_dset = DisjointIntervalSet(k_limit=8)
        for d_int in dest_dset.intervals:
            res = zero_int.sub(d_int)
            for r in res.intervals:
                new_dset.add(r)
        set_dest_dset(state, dest, new_dset, size)

    @staticmethod
    def eval_shift_op(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int, shift_type: str) -> None:
        if len(operands) < 2:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        dest_dset = get_dest_dset(state, dest)
        if not dest_dset:
            return

        shift = operands[1]['value'] if operands[1]['type'] == 'imm' else 0
        new_dset = DisjointIntervalSet(k_limit=8)

        if shift_type == 'shl':
            for iv in dest_dset.intervals:
                new_dset.add(Interval((iv.min_val << shift) & 0xFFFFFFFF, (iv.max_val << shift) & 0xFFFFFFFF, bit_width=64))
        elif shift_type == 'shr':
            for iv in dest_dset.intervals:
                new_dset.add(Interval((iv.min_val >> shift) & 0xFFFFFFFF, (iv.max_val >> shift) & 0xFFFFFFFF, bit_width=64))
        elif shift_type == 'sar':
            bit_w = size * 8
            def to_s(v):
                v &= (1 << bit_w) - 1
                return v - (1 << bit_w) if v >= (1 << (bit_w - 1)) else v
            for iv in dest_dset.intervals:
                s_min = (to_s(iv.min_val) >> shift) & ((1 << bit_w) - 1)
                s_max = (to_s(iv.max_val) >> shift) & ((1 << bit_w) - 1)
                new_dset.add(Interval(min(s_min, s_max), max(s_min, s_max), bit_width=64))

        set_dest_dset(state, dest, new_dset, size)

    @staticmethod
    def eval_mov(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int) -> None:
        if len(operands) < 2:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        src_dset = get_src_dset(state, record, operands[1])
        if src_dset:
            set_dest_dset(state, dest, copy.deepcopy(src_dset), size)

    @staticmethod
    def eval_movzx(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int) -> None:
        if len(operands) < 2:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        src_dset = get_src_dset(state, record, operands[1])
        if src_dset:
            src_size = operands[1].get('size', size)
            val_mask = (1 << (src_size * 8)) - 1
            new_dset = DisjointIntervalSet(k_limit=8)
            for iv in src_dset.intervals:
                new_dset.add(Interval(iv.min_val & val_mask, iv.max_val & val_mask, bit_width=size * 8))
            set_dest_dset(state, dest, new_dset, size)

    @staticmethod
    def eval_movsx(record: Any, state: AbstractState, operands: List[Dict[str, Any]], size: int) -> None:
        if len(operands) < 2:
            return
        dest = get_op_key(record, operands[0], is_dest=True)
        if not dest:
            return
        src_dset = get_src_dset(state, record, operands[1])
        if src_dset:
            src_size = operands[1].get('size', 4)
            src_bits = src_size * 8
            sign_mask = 1 << (src_bits - 1)
            val_mask = (1 << src_bits) - 1
            dst_bits = size * 8 if size >= src_size else 64
            dst_mask = (1 << dst_bits) - 1
            new_dset = DisjointIntervalSet(k_limit=8)
            for iv in src_dset.intervals:
                v = iv.min_val & val_mask
                s = (v - (1 << src_bits)) if v >= sign_mask else v
                s &= dst_mask
                new_dset.add(Interval(s, s, bit_width=dst_bits))
            set_dest_dset(state, dest, new_dset, dst_size=dst_bits // 8)

    @classmethod
    def dispatch(cls, record: Any, state: AbstractState) -> None:
        """
        Instruction Dispatcher. Maps x86 instructions to VSA Mathematical Primitives.
        """
        mnemonic = getattr(record, 'mnemonic', '').lower()
        operands = get_operand_list(record)
        if not operands:
            return

        size = operands[0].get('size', 4)

        if mnemonic == 'mov':
            cls.eval_mov(record, state, operands, size)
        elif mnemonic == 'movzx':
            cls.eval_movzx(record, state, operands, size)
        elif mnemonic in ('movsxd', 'movsx'):
            cls.eval_movsx(record, state, operands, size)
        elif mnemonic == 'cbw':
            sign_extend_acc(state, 'al', 'ax', 8, 16)
        elif mnemonic == 'cwde':
            sign_extend_acc(state, 'ax', 'eax', 16, 32)
        elif mnemonic == 'cdqe':
            sign_extend_acc(state, 'eax', 'rax', 32, 64)
        elif mnemonic == 'cwd':
            sign_extend_hi(state, 'ax', 'dx', 16)
        elif mnemonic == 'cdq':
            sign_extend_hi(state, 'eax', 'edx', 32)
        elif mnemonic == 'cqo':
            sign_extend_hi(state, 'rax', 'rdx', 64)
        elif mnemonic == 'add':
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.add(s))
        elif mnemonic == 'sub':
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.sub(s))
        elif mnemonic in ('imul', 'mul'):
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.mul(s))
        elif mnemonic == 'neg':
            cls.eval_neg_op(record, state, operands, size)
        elif mnemonic == 'xor':
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.bitwise_xor(s))
        elif mnemonic == 'and':
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.bitwise_and(s))
        elif mnemonic == 'or':
            cls.eval_binary_op(record, state, operands, size, lambda d, s: d.bitwise_or(s))
        elif mnemonic == 'inc':
            cls.eval_unary_op(record, state, operands, size, is_inc=True)
        elif mnemonic == 'dec':
            cls.eval_unary_op(record, state, operands, size, is_inc=False)
        elif mnemonic == 'shl':
            cls.eval_shift_op(record, state, operands, size, 'shl')
        elif mnemonic == 'shr':
            cls.eval_shift_op(record, state, operands, size, 'shr')
        elif mnemonic == 'sar':
            cls.eval_shift_op(record, state, operands, size, 'sar')
