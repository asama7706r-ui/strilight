import copy
from typing import Optional, List, Dict, Any
from strilight.engine.abstract_state import AbstractState
from strilight.pruning.interval import Interval, DisjointIntervalSet
from strilight.engine.x86_defs import REG_TO_BASE, REGISTER_SIZES, get_register_mask


def get_operand_list(record: Any) -> List[Dict[str, Any]]:
    """Extracts parsed operands from a trace record or parses `op_str` fallback."""
    if getattr(record, 'operands', None) and len(record.operands) > 0:
        return record.operands
    ops = []
    if getattr(record, 'op_str', None):
        tokens = [t.strip() for t in record.op_str.split(',') if t.strip()]
        for tok in tokens:
            try:
                if tok.startswith('0x') or tok.startswith('-0x'):
                    ops.append({'type': 'imm', 'value': int(tok, 16)})
                elif tok.isdigit() or (tok.startswith('-') and tok[1:].isdigit()):
                    ops.append({'type': 'imm', 'value': int(tok, 10)})
                elif tok.startswith('[') and tok.endswith(']'):
                    addr_str = tok[1:-1].strip()
                    addr_val = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                    ops.append({'type': 'mem', 'value': addr_val, 'size': getattr(record, 'size', 4)})
                else:
                    ops.append({'type': 'reg', 'value': tok, 'size': getattr(record, 'size', 4)})
            except Exception:
                ops.append({'type': 'reg', 'value': tok, 'size': getattr(record, 'size', 4)})
    return ops


def get_op_key(record: Any, op: Dict[str, Any], is_dest: bool = False) -> Optional[str]:
    """Resolves an operand dict to its register name or memory key string."""
    if op['type'] == 'reg':
        return op['value']
    elif op['type'] == 'mem':
        addr_list = record.mem_write if is_dest else record.mem_read
        if addr_list:
            addr = addr_list[0]
        else:
            addr = op.get('value', 0)
        mem_size = op.get('size', 4) * 8
        return f"MEM_{addr}_{mem_size}"
    return None


def get_dest_dset(state: AbstractState, dest_key: str) -> Optional[DisjointIntervalSet]:
    """Retrieves the DisjointIntervalSet for a destination register or its base."""
    res = state.get_register(dest_key)
    if res:
        return res
    base = REG_TO_BASE.get(dest_key, dest_key)
    return state.get_register(base)


def set_dest_dset(state: AbstractState, dest_key: str, new_dset: DisjointIntervalSet, dst_size: int = 4) -> None:
    """
    Sets a destination register's interval set with x86 sub-register blending & zero-extension semantics.
    """
    state.set_register(dest_key, new_dset)
    if dest_key in REG_TO_BASE:
        base = REG_TO_BASE[dest_key]
        reg_size = REGISTER_SIZES.get(dest_key.lower(), dst_size)
        if reg_size >= 4:
            # 32-bit writes in x86_64 zero-extend to 64-bit and wipe upper 32 bits
            # 64-bit writes replace base directly
            if reg_size == 4:
                base_dset = DisjointIntervalSet(k_limit=8)
                for iv in new_dset.intervals:
                    base_dset.add(iv.zero_extend(src_bit_width=32, dst_bit_width=64))
                state.set_register(base, base_dset)
            else:
                state.set_register(base, copy.deepcopy(new_dset))
        else:
            # 8-bit / 16-bit writes: preserve untouched upper bits in base register!
            mask = get_register_mask(dest_key)
            current_base_dset = state.get_register(base)
            if current_base_dset and current_base_dset.intervals:
                blended_dset = DisjointIntervalSet(k_limit=8)
                for base_iv in current_base_dset.intervals:
                    for sub_iv in new_dset.intervals:
                        blended_dset.add(base_iv.blend(sub_iv, mask))
                state.set_register(base, blended_dset)
            else:
                state.set_register(base, copy.deepcopy(new_dset))


def get_src_dset(state: AbstractState, record: Any, src_op: Dict[str, Any]) -> Optional[DisjointIntervalSet]:
    """Retrieves or creates the source operand's DisjointIntervalSet."""
    if src_op['type'] == 'imm':
        val = src_op['value']
        d = DisjointIntervalSet(k_limit=8)
        d.add(Interval(val, val))
        return d
    elif src_op['type'] in ('reg', 'mem'):
        src_key = get_op_key(record, src_op, is_dest=False)
        if src_key:
            res = state.get_register(src_key)
            if res:
                return res
            base = REG_TO_BASE.get(src_key, src_key)
            return state.get_register(base)
    return None


def sign_extend_acc(state: AbstractState, src_name: str, dst_name: str, src_bits: int, dst_bits: int) -> None:
    """Sign-extends accumulator registers (e.g. cbw, cwde, cdqe)."""
    src_dset = state.get_register(src_name) or state.get_register(REG_TO_BASE.get(src_name, src_name))
    if src_dset:
        sign_mask = 1 << (src_bits - 1)
        val_mask = (1 << src_bits) - 1
        dst_mask = (1 << dst_bits) - 1
        new_dset = DisjointIntervalSet(k_limit=8)
        for iv in src_dset.intervals:
            v = iv.min_val & val_mask
            s = (v - (1 << src_bits)) if v >= sign_mask else v
            s &= dst_mask
            new_dset.add(Interval(s, s, bit_width=dst_bits))
        set_dest_dset(state, dst_name, new_dset, dst_size=dst_bits // 8)


def sign_extend_hi(state: AbstractState, src_name: str, hi_name: str, src_bits: int) -> None:
    """Sign-extends to high-word registers (e.g. cwd, cdq, cqo)."""
    src_dset = state.get_register(src_name) or state.get_register(REG_TO_BASE.get(src_name, src_name))
    if src_dset:
        sign_mask = 1 << (src_bits - 1)
        val_mask = (1 << src_bits) - 1
        new_dset = DisjointIntervalSet(k_limit=8)
        for iv in src_dset.intervals:
            v = iv.min_val & val_mask
            hi = val_mask if v >= sign_mask else 0
            new_dset.add(Interval(hi, hi, bit_width=src_bits))
        set_dest_dset(state, hi_name, new_dset, dst_size=src_bits // 8)
