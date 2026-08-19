import copy
from typing import Dict, Optional, List, TYPE_CHECKING
if TYPE_CHECKING:
    from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.abstract_state import AbstractState
from asm_analyzer.pruning.interval import Interval, DisjointIntervalSet
from asm_analyzer.engine.loop_compressor import LoopBlock
from asm_analyzer.engine.x86_defs import get_instruction_type, get_flags_read
from asm_analyzer.engine.tracker_bridge import TrackerBridge
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
    def __init__(self):
        pass
        
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
        # Initial Blank Slate
        state_0 = AbstractState()
        
        # Pre-initialize registers and active memory to Symbolic Zero [0, 0] to extract relative Deltas
        self._extract_ops(loop_block.body, state_0)
            
        # Run K passes (K = 8) to discover scalar deltas and polycyclic periodic stride patterns
        K = 8
        passes = [state_0]
        for _ in range(K):
            next_state = self._run_pass(loop_block.body, passes[-1])
            passes.append(next_state)
        
        summary = LoopSummary()
        
        # Collect all active registers and memory locations across passes
        all_tracked = set()
        for st in passes:
            all_tracked.update(st.registers.keys())
            
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
                
            # 3. Compute step differences (Delta per step) in 64-bit two's complement
            def to_signed(val: int, bit_width: int = 64) -> int:
                mask = (1 << bit_width) - 1
                v = val & mask
                if v >= (1 << (bit_width - 1)):
                    return v - (1 << bit_width)
                return v

            step_deltas = [to_signed(values[i] - values[i - 1]) for i in range(1, len(values))]
            
            # 4. Check for Scalar Delta (P = 1)
            if all(d == step_deltas[0] for d in step_deltas):
                summary.deltas[reg_name] = step_deltas[0]
                print(f"  [LoopEvaluator] Extracted Scalar Delta for {reg_name}: {step_deltas[0]}")
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
                print(f"  [LoopEvaluator] Extracted Polycyclic Pattern for {reg_name}: {found_period} (Period P={len(found_period)}, Sum={sum(found_period)})")
                        
        # Delegate ALL control flow and condition analysis to the tracking facade
        cond_str, exit_records = TrackerBridge.evaluate_loop_exit(loop_block)
        print(f"\n[DEBUG TRACKER_BRIDGE] cond_str: {cond_str}")
        print(f"[DEBUG TRACKER_BRIDGE] exit_records: {exit_records}")
        if cond_str:
            summary.exit_condition = cond_str
            summary.exit_records = exit_records
                
        summary.iterations = loop_block.iterations
        return summary

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
        
    def _dispatch_instruction(self, record, state: AbstractState):
        """
        Instruction Dispatcher. Maps x86 instructions to VSA Mathematical Primitives.
        """
        mnemonic = record.mnemonic.lower()
        
        def _get_operand_list():
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

        operands = _get_operand_list()

        def get_op_key(op, is_dest=False):
            if op['type'] == 'reg':
                return op['value']
            elif op['type'] == 'mem':
                addr_list = record.mem_write if is_dest else record.mem_read
                if addr_list:
                    addr = addr_list[0]
                else:
                    addr = op.get('value', 0)
                size = op.get('size', 4) * 8
                return f"MEM_{addr}_{size}"
            return None

        if mnemonic == "add" and len(operands) == 2:
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_op = operands[1]
            dest_dset = state.get_register(dest)
            if not dest_dset: return
            
            if src_op['type'] == 'imm':
                val = src_op['value']
                src_int = Interval(val, val)
                
                # Apply addition to all disjoint fragments
                new_dset = DisjointIntervalSet(k_limit=8)
                for i in dest_dset.intervals:
                    res = i.add(src_int)
                    for r in res.intervals:
                        new_dset.add(r)
                state.set_register(dest, new_dset)
                
        elif mnemonic == "sub" and len(operands) == 2:
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_op = operands[1]
            dest_dset = state.get_register(dest)
            if not dest_dset: return
            
            if src_op['type'] == 'imm':
                val = src_op['value']
                src_int = Interval(val, val)
                
                new_dset = DisjointIntervalSet(k_limit=8)
                for i in dest_dset.intervals:
                    res = i.sub(src_int)
                    for r in res.intervals:
                        new_dset.add(r)
                state.set_register(dest, new_dset)
                
        elif mnemonic == "mov" and len(operands) == 2:
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            src_op = operands[1]
            
            if src_op['type'] == 'imm':
                val = src_op['value']
                new_dset = DisjointIntervalSet(k_limit=8)
                new_dset.add(Interval(val, val))
                state.set_register(dest, new_dset)
            elif src_op['type'] == 'reg' or src_op['type'] == 'mem':
                src = get_op_key(src_op, is_dest=False)
                if src:
                    src_dset = state.get_register(src)
                    if src_dset:
                        state.set_register(dest, copy.deepcopy(src_dset))

        elif mnemonic == "inc" and len(operands) == 1:
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = state.get_register(dest)
            if not dest_dset: return
            src_int = Interval(1, 1)
            new_dset = DisjointIntervalSet(k_limit=8)
            for i in dest_dset.intervals:
                res = i.add(src_int)
                for r in res.intervals:
                    new_dset.add(r)
            state.set_register(dest, new_dset)

        elif mnemonic == "dec" and len(operands) == 1:
            dest = get_op_key(operands[0], is_dest=True)
            if not dest: return
            dest_dset = state.get_register(dest)
            if not dest_dset: return
            src_int = Interval(1, 1)
            new_dset = DisjointIntervalSet(k_limit=8)
            for i in dest_dset.intervals:
                res = i.sub(src_int)
                for r in res.intervals:
                    new_dset.add(r)
            state.set_register(dest, new_dset)
