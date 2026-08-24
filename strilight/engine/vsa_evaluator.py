import copy
import logging
from typing import Dict, Optional, List, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from strilight.engine.tracker import TraceRecord
from strilight.engine.abstract_state import AbstractState
from strilight.pruning.interval import Interval, DisjointIntervalSet
from strilight.engine.loop_compressor import LoopBlock
from strilight.engine.x86_defs import get_instruction_type, get_flags_read, REG_TO_BASE, REGISTER_SIZES, get_register_mask
from strilight.engine.tracker_bridge import TrackerBridge

logger = logging.getLogger("strilight.engine.vsa_evaluator")
class LoopInvariantContract:
    """
    Explicit mathematical contract for loop invariants and exact termination boundaries.
    Provides closed-form induction formulas for both iteration N and iteration N-1 (the Iron Constraint).
    """
    def __init__(self, summary: 'LoopSummary'):
        self.summary = summary

    def get_induction_formulas(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns the closed-form transition equations for each induction variable:
        - At iteration N: State(N) = State_0 + Delta * N
        - At iteration N-1 (Pre-exit Iron State): State(N-1) = State_0 + Delta * (N - 1)
        """
        formulas = {}
        for var, delta in self.summary.deltas.items():
            formulas[var] = {
                "delta": delta,
                "formula_at_N": f"{var}_0 + ({delta}) * N",
                "formula_at_N_minus_1": f"{var}_0 + ({delta}) * (N - 1)"
            }
        for var, pattern in self.summary.patterns.items():
            p_len = len(pattern)
            p_sum = sum(pattern)
            formulas[var] = {
                "pattern": pattern,
                "period": p_len,
                "cycle_sum": p_sum,
                "formula_at_N": f"{var}_0 + (N // {p_len}) * {p_sum} + prefix_sum(N % {p_len})",
                "formula_at_N_minus_1": f"{var}_0 + ((N - 1) // {p_len}) * {p_sum} + prefix_sum((N - 1) % {p_len})"
            }
        for var, const_val in self.summary.constant_sets.items():
            formulas[var] = {
                "constant": const_val,
                "formula_at_N": str(const_val),
                "formula_at_N_minus_1": str(const_val)
            }
        return formulas

    def get_exit_invariant_rule(self) -> str:
        """
        The fundamental Iron Constraint:
        A loop terminating strictly at iteration N requires:
        1. ExitCondition(State(N)) == True  [The exit branch is taken / header condition fails]
        2. ExitCondition(State(N-1)) == False for N > 0  [The loop was NOT exited prematurely at iteration N-1]
        """
        cond_str = self.summary.exit_condition or "Unknown Exit"
        return (
            f"Iron Constraint: Enforce [{cond_str}] evaluated at State(N) == True "
            f"AND Implies(N > 0, [{cond_str}] evaluated at State(N-1) == False)"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the invariant contract into a standard dictionary/JSON format."""
        exit_instructions = []
        for r in getattr(self.summary, 'exit_records', []):
            if hasattr(r, 'mnemonic'):
                exit_instructions.append({
                    "address": getattr(r, 'address', 0),
                    "mnemonic": getattr(r, 'mnemonic', ''),
                    "op_str": getattr(r, 'op_str', ''),
                    "jump_taken": getattr(r, 'jump_taken', False)
                })
        return {
            "exit_condition_text": self.summary.exit_condition,
            "exit_instructions": exit_instructions,
            "induction_formulas": self.get_induction_formulas(),
            "iron_constraint_rule": self.get_exit_invariant_rule(),
            "iterations_bound": self.summary.iterations
        }


class LoopSummary:
    """
    Symbolic mathematical summary of a loop's effect.
    This is passed to the BackwardTracker (or Translator) to instantly jump over the loop.
    """
    def __init__(self):
        # Maps register name to its extracted symbolic delta per iteration (e.g., EAX increases by 4)
        self.deltas: Dict[str, int] = {}
        
        # Maps register name to periodic polycyclic pattern (e.g., EAX increases by [5, 4, 8, 1])
        self.patterns: Dict[str, List[int]] = {}
        
        # Values that are set to a constant and don't change
        self.constant_sets: Dict[str, int] = {}
        
        # The exit condition string (e.g., "cmp ecx, 10 -> jne")
        self.exit_condition: Optional[str] = None
        
        # Original TraceRecords for the exit condition (e.g. cmp and jcc instructions)
        # to be passed to the Z3 Translator
        self.exit_records: List['TraceRecord'] = []
        
        # The dynamic number of iterations this loop ran
        self.iterations: int = 0
        
        # Nested inner loop summaries
        self.inner_summaries: List['LoopSummary'] = []
        self.direct_deltas: Dict[str, int] = {}
        self.direct_patterns: Dict[str, List[int]] = {}
        self.direct_constant_sets: Dict[str, int] = {}
        self.tick: Optional[int] = None

    @property
    def invariant_contract(self) -> LoopInvariantContract:
        """Returns the formal mathematical invariant contract for this loop."""
        return LoopInvariantContract(self)

    def get_invariant_contract(self) -> LoopInvariantContract:
        """Helper to retrieve the formal mathematical invariant contract."""
        return LoopInvariantContract(self)


class LoopEvaluator:
    """
    Evaluates the abstract state of a loop across multiple iterations (Passes).
    
    [ARCHITECTURAL NOTE FOR FUTURE AGENTS]:
    This is purely a DATA-FLOW ENGINE. It simulates mathematical instructions (add, sub, etc.) 
    using Value Set Analysis (VSA) bounds to extract strides (deltas) and polycyclic patterns. 
    It NEVER reads conditional flags (ZF, CF) and NEVER executes control-flow instructions (jcc).
    Conditional loop-exit instructions are simply bundled into `summary.exit_records` and handed 
    over to `Z3Translator` for actual mathematical control-flow translation.
    """
    def __init__(self, k_passes: int = 100):
        self.k_passes = k_passes
        
    def _extract_ops(self, body, state_0):
        for record in body:
            if hasattr(record, 'body'):
                self._extract_ops(record.body, state_0)
                continue
            for is_dst, ops in [(False, getattr(record, 'regs_read', [])), (True, getattr(record, 'regs_write', []))]:
                for reg in ops:
                    if reg not in state_0.registers:
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, 0))
                        state_0.set_register(reg, dset)
            
            for is_dst, mems in [(False, getattr(record, 'mem_read', [])), (True, getattr(record, 'mem_write', []))]:
                for mem in mems:
                    size = getattr(record, 'size', 4) * 8
                    for op in getattr(record, 'operands', []):
                        if op.get('type') == 'mem': size = op.get('size', 4) * 8
                    key = f"MEM_{mem}_{size}"
                    if key not in state_0.registers:
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, 0))
                        state_0.set_register(key, dset)
                        
            # Fallback from op_str if operands / regs_write were empty (e.g. in mock test records)
            if not getattr(record, 'regs_write', []) and not getattr(record, 'operands', []) and getattr(record, 'op_str', None):
                parts = [p.strip() for p in record.op_str.split(',')]
                if parts and parts[0] and not parts[0].isdigit() and not parts[0].startswith('0x'):
                    reg = parts[0]
                    if reg not in state_0.registers:
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, 0))
                        state_0.set_register(reg, dset)

    def evaluate(self, loop_block: LoopBlock) -> LoopSummary:
        # Fast path: return an isolated copy of pre-computed mathematical summary
        if getattr(loop_block, '_cached_summary', None) is not None:
            return copy.copy(loop_block._cached_summary)

        # Initial Blank Slate
        state_0 = AbstractState()
        
        # Pre-initialize registers and active memory to Symbolic Zero [0, 0] to extract relative Deltas
        self._extract_ops(loop_block.body, state_0)
            
        # Run K passes (K = 100) to discover scalar deltas and polycyclic periodic stride patterns
        K = getattr(self, 'k_passes', 100)
        passes = [state_0]
        for _ in range(K):
            next_state = self._run_pass(loop_block.body, passes[-1])
            passes.append(next_state)
        
        summary = LoopSummary()
        
        # Collect all active registers and memory locations across passes
        all_tracked = set()
        for st in passes:
            all_tracked.update(st.registers.keys())
            
        def to_signed(val: int, bit_width: int = 64) -> int:
            mask = (1 << bit_width) - 1
            v = val & mask
            if v >= (1 << (bit_width - 1)):
                return v - (1 << bit_width)
            return v
            
        # Extract Stride Deltas & Polycyclic Patterns
        for reg_name in all_tracked:
            values = []
            valid = True
            for st in passes:
                dset = st.registers.get(reg_name)
                if dset and len(dset.intervals) == 1 and dset.intervals[0].min_val == dset.intervals[0].max_val:
                    values.append(dset.intervals[0].min_val)
                else:
                    valid = False
                    break
                    
            if not valid or len(values) < K + 1:
                continue
                
            v0 = values[0]
            
            # 1. Check if unmodified throughout the loop (remains identical to state_0)
            if all(v == v0 for v in values):
                continue
                
            # 2. Check if Constant Set (changed in Pass 1, but remained constant in all subsequent passes)
            if all(v == values[1] for v in values[1:]):
                summary.constant_sets[reg_name] = values[1]
                continue
                
            step_deltas = [to_signed(values[i] - values[i - 1]) for i in range(1, len(values))]
            
            # 4. Check for Scalar Delta (P = 1)
            if all(d == step_deltas[0] for d in step_deltas):
                summary.deltas[reg_name] = step_deltas[0]
                logger.debug("Extracted Scalar Delta for %s: %s", reg_name, step_deltas[0])
                continue
                
            # 5. Check for Polycyclic Stride Pattern (P >= 2)
            found_period = None
            for P in range(2, (len(step_deltas) // 2) + 1):
                pattern_candidate = step_deltas[:P]
                is_periodic = True
                for idx in range(P, len(step_deltas)):
                    if step_deltas[idx] != pattern_candidate[idx % P]:
                        is_periodic = False
                        break
                if is_periodic:
                    found_period = pattern_candidate
                    break
                    
            if found_period is not None:
                summary.patterns[reg_name] = found_period
                logger.debug("Extracted Polycyclic Pattern for %s: %s (Period P=%d, Sum=%d)", reg_name, found_period, len(found_period), sum(found_period))
                
        # Discover child inner loops
        for item in loop_block.body:
            if hasattr(item, 'body'):
                inner_sum = self.evaluate(item)
                inner_sum.tick = getattr(item, 'start_tick', 0)
                summary.inner_summaries.append(inner_sum)
                
        # If there are inner loops, also extract direct deltas from outer non-loop instructions
        if summary.inner_summaries:
            direct_body = [r for r in loop_block.body if not hasattr(r, 'body')]
            if direct_body:
                direct_state_0 = AbstractState()
                self._extract_ops(direct_body, direct_state_0)
                direct_passes = [direct_state_0]
                for _ in range(K):
                    next_st = self._run_pass(direct_body, direct_passes[-1])
                    direct_passes.append(next_st)
                    
                direct_all = set().union(*(st.registers.keys() for st in direct_passes))
                for reg_name in direct_all:
                    vals = []
                    v_ok = True
                    for st in direct_passes:
                        ds = st.registers.get(reg_name)
                        if ds and len(ds.intervals) == 1 and ds.intervals[0].min_val == ds.intervals[0].max_val:
                            vals.append(ds.intervals[0].min_val)
                        else:
                            v_ok = False
                            break
                    if v_ok and len(vals) == K + 1 and not all(v == vals[0] for v in vals):
                        if all(v == vals[1] for v in vals[1:]):
                            summary.direct_constant_sets[reg_name] = vals[1]
                        else:
                            sd = [to_signed(vals[i] - vals[i-1]) for i in range(1, len(vals))]
                            if all(d == sd[0] for d in sd):
                                summary.direct_deltas[reg_name] = sd[0]
                                logger.debug("Extracted Direct Outer Delta for %s: %s", reg_name, sd[0])
                        
        # Delegate ALL control flow and condition analysis to the tracking facade
        cond_str, exit_records = TrackerBridge.evaluate_loop_exit(loop_block, induction_vars=set(summary.deltas.keys()))
        logger.debug("cond_str: %s", cond_str)
        logger.debug("exit_records: %s", exit_records)
        if cond_str:
            summary.exit_condition = cond_str
            summary.exit_records = exit_records
                
        summary.iterations = loop_block.iterations
        loop_block._cached_summary = summary
        return copy.copy(summary)

    def _run_pass(self, body, state: AbstractState) -> AbstractState:
        # Deepcopy the state to isolate iterations
        new_state = copy.deepcopy(state)
        
        for record in body:
            if hasattr(record, 'body'):
                # Nested inner LoopBlock
                inner_summary = self.evaluate(record)
                
                # Apply inner loop's scalar deltas mathematically
                for reg_name, delta in inner_summary.deltas.items():
                    dest_dset = new_state.get_register(reg_name)
                    if dest_dset:
                        total_delta = delta * getattr(record, 'iterations', 0)
                        src_int = Interval(total_delta, total_delta)
                        new_dset = DisjointIntervalSet(k_limit=8)
                        for i in dest_dset.intervals:
                            res = i.add(src_int)
                            for r in res.intervals:
                                new_dset.add(r)
                        new_state.set_register(reg_name, new_dset)
                        
                # Apply inner loop's polycyclic patterns mathematically via Closed-Form
                for reg_name, pattern in inner_summary.patterns.items():
                    dest_dset = new_state.get_register(reg_name)
                    if dest_dset:
                        P = len(pattern)
                        N_inner = getattr(record, 'iterations', 0)
                        Q = N_inner // P
                        R = N_inner % P
                        total_delta = Q * sum(pattern) + sum(pattern[:R])
                        src_int = Interval(total_delta, total_delta)
                        new_dset = DisjointIntervalSet(k_limit=8)
                        for i in dest_dset.intervals:
                            res = i.add(src_int)
                            for r in res.intervals:
                                new_dset.add(r)
                        new_state.set_register(reg_name, new_dset)
                        
                # Apply inner loop's constant sets
                for reg_name, const_val in inner_summary.constant_sets.items():
                    new_dset = DisjointIntervalSet(k_limit=8)
                    new_dset.add(Interval(const_val, const_val))
                    new_state.set_register(reg_name, new_dset)
            else:
                self._dispatch_instruction(record, new_state)
            
        return new_state
        
    def _get_operand_list(self, record):
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

    def _dispatch_instruction(self, record, state: AbstractState):
        """
        Instruction Dispatcher. Maps x86 instructions to VSA Mathematical Primitives.
        """
        mnemonic = record.mnemonic.lower()
        operands = self._get_operand_list(record)
        if not operands:
            return

        size = operands[0].get('size', 4)

        def get_op_key(op, is_dest=False):
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

        def get_dest_dset(dest_key):
            res = state.get_register(dest_key)
            if res: return res
            base = REG_TO_BASE.get(dest_key, dest_key)
            return state.get_register(base)

        def set_dest_dset(dest_key, new_dset, dst_size=4):
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

        def get_src_dset(src_op):
            if src_op['type'] == 'imm':
                val = src_op['value']
                d = DisjointIntervalSet(k_limit=8)
                d.add(Interval(val, val))
                return d
            elif src_op['type'] in ('reg', 'mem'):
                src_key = get_op_key(src_op, is_dest=False)
                if src_key:
                    res = state.get_register(src_key)
                    if res: return res
                    base = REG_TO_BASE.get(src_key, src_key)
                    return state.get_register(base)
            return None

        # Generic Helper for Binary Arithmetic & Bitwise Logic
        def _eval_binary_op(op_func):
            if len(operands) < 2: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = get_dest_dset(dest)
            if not dest_dset: return
            src_dset = get_src_dset(operands[1])
            if not src_dset: return

            new_dset = DisjointIntervalSet(k_limit=8)
            for d_int in dest_dset.intervals:
                for s_int in src_dset.intervals:
                    res = op_func(d_int, s_int)
                    if isinstance(res, DisjointIntervalSet):
                        for r in res.intervals:
                            new_dset.add(r)
                    elif res is not None:
                        new_dset.add(res)
            set_dest_dset(dest, new_dset, size)

        # Generic Helper for Unary Increment/Decrement
        def _eval_unary_op(is_inc: bool):
            if len(operands) < 1: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = get_dest_dset(dest)
            if not dest_dset: return

            step_int = Interval(1, 1)
            new_dset = DisjointIntervalSet(k_limit=8)
            for d_int in dest_dset.intervals:
                res = d_int.add(step_int) if is_inc else d_int.sub(step_int)
                for r in res.intervals:
                    new_dset.add(r)
            set_dest_dset(dest, new_dset, size)

        def _eval_neg_op():
            if len(operands) < 1: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = get_dest_dset(dest)
            if not dest_dset: return
            zero_int = Interval(0, 0)
            new_dset = DisjointIntervalSet(k_limit=8)
            for d_int in dest_dset.intervals:
                res = zero_int.sub(d_int)
                for r in res.intervals:
                    new_dset.add(r)
            set_dest_dset(dest, new_dset, size)

        # Generic Helper for Bit Shifts
        def _eval_shift_op(shift_type: str):
            if len(operands) < 2: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = get_dest_dset(dest)
            if not dest_dset: return

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

            set_dest_dset(dest, new_dset, size)

        # Dedicated Data Movement Handlers
        def _eval_mov():
            if len(operands) < 2: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_dset = get_src_dset(operands[1])
            if src_dset:
                set_dest_dset(dest, copy.deepcopy(src_dset), size)

        def _eval_movzx():
            if len(operands) < 2: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_dset = get_src_dset(operands[1])
            if src_dset:
                src_size = operands[1].get('size', size)
                val_mask = (1 << (src_size * 8)) - 1
                new_dset = DisjointIntervalSet(k_limit=8)
                for iv in src_dset.intervals:
                    new_dset.add(Interval(iv.min_val & val_mask, iv.max_val & val_mask, bit_width=size * 8))
                set_dest_dset(dest, new_dset, size)

        def _eval_movsx():
            if len(operands) < 2: return
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_dset = get_src_dset(operands[1])
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
                set_dest_dset(dest, new_dset, dst_size=dst_bits // 8)

        def _eval_sign_extend_acc(src_name, dst_name, src_bits, dst_bits):
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
                set_dest_dset(dst_name, new_dset, dst_size=dst_bits // 8)

        def _eval_sign_extend_hi(src_name, hi_name, src_bits):
            src_dset = state.get_register(src_name) or state.get_register(REG_TO_BASE.get(src_name, src_name))
            if src_dset:
                sign_mask = 1 << (src_bits - 1)
                val_mask = (1 << src_bits) - 1
                new_dset = DisjointIntervalSet(k_limit=8)
                for iv in src_dset.intervals:
                    v = iv.min_val & val_mask
                    hi = val_mask if v >= sign_mask else 0
                    new_dset.add(Interval(hi, hi, bit_width=src_bits))
                set_dest_dset(hi_name, new_dset, dst_size=src_bits // 8)

        # Categorized Handler Dispatch Table
        handlers = {
            # Data Movement & Extension
            'mov': _eval_mov,
            'movzx': _eval_movzx,
            'movsxd': _eval_movsx,
            'movsx': _eval_movsx,
            'cbw': lambda: _eval_sign_extend_acc('al', 'ax', 8, 16),
            'cwde': lambda: _eval_sign_extend_acc('ax', 'eax', 16, 32),
            'cdqe': lambda: _eval_sign_extend_acc('eax', 'rax', 32, 64),
            'cwd': lambda: _eval_sign_extend_hi('ax', 'dx', 16),
            'cdq': lambda: _eval_sign_extend_hi('eax', 'edx', 32),
            'cqo': lambda: _eval_sign_extend_hi('rax', 'rdx', 64),

            # Arithmetic & Bitwise Logic
            'add': lambda: _eval_binary_op(lambda d, s: d.add(s)),
            'sub': lambda: _eval_binary_op(lambda d, s: d.sub(s)),
            'imul': lambda: _eval_binary_op(lambda d, s: d.mul(s)),
            'mul': lambda: _eval_binary_op(lambda d, s: d.mul(s)),
            'neg': _eval_neg_op,
            'xor': lambda: _eval_binary_op(lambda d, s: d.bitwise_xor(s)),
            'and': lambda: _eval_binary_op(lambda d, s: d.bitwise_and(s)),
            'or':  lambda: _eval_binary_op(lambda d, s: d.bitwise_or(s)),
            'inc': lambda: _eval_unary_op(is_inc=True),
            'dec': lambda: _eval_unary_op(is_inc=False),

            # Shifts
            'shl': lambda: _eval_shift_op('shl'),
            'shr': lambda: _eval_shift_op('shr'),
            'sar': lambda: _eval_shift_op('sar'),
        }

        handler = handlers.get(mnemonic)
        if handler:
            handler()
