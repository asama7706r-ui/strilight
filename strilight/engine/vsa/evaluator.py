import copy
import logging
from typing import Optional, List, Any
from strilight.engine.abstract_state import AbstractState
from strilight.pruning.interval import Interval, DisjointIntervalSet
from strilight.engine.loop_compressor import LoopBlock
from strilight.engine.tracker_bridge import TrackerBridge
from strilight.engine.vsa.models import LoopSummary
from strilight.engine.vsa.state_ops import get_operand_list
from strilight.engine.vsa.dispatcher import VSAInstructionDispatcher
from strilight.engine.vsa.symbolic import SymbolicInductionAnalyzer

logger = logging.getLogger("strilight.engine.vsa.evaluator")


class LoopEvaluator:
    """
    Evaluates the abstract state of a loop across multiple iterations (Passes).
    Upgraded with Single-Pass Symbolic Induction (Zero-Spinning).
    
    [ARCHITECTURAL NOTE FOR FUTURE AGENTS]:
    This is purely a DATA-FLOW ENGINE. It simulates mathematical instructions (add, sub, etc.) 
    using Value Set Analysis (VSA) bounds to extract strides (deltas) and polycyclic patterns. 
    It NEVER reads conditional flags (ZF, CF) and NEVER executes control-flow instructions (jcc).
    Conditional loop-exit instructions are simply bundled into `summary.exit_records` and handed 
    over to `Z3Translator` for actual mathematical control-flow translation.
    """
    def __init__(self, k_passes: int = 100, memory_provider: Optional[Any] = None):
        self.k_passes = k_passes
        self.memory_provider = memory_provider

    def _get_operand_list(self, record: Any) -> List[Any]:
        """Helper to extract operands list (delegated to state_ops)."""
        return get_operand_list(record)

    def _dispatch_instruction(self, record: Any, state: AbstractState) -> None:
        """Instruction dispatcher (delegated to VSAInstructionDispatcher)."""
        VSAInstructionDispatcher.dispatch(record, state)

    def _evaluate_symbolic_pass(self, body: List[Any], summary: LoopSummary) -> bool:
        """Executes a single symbolic pass over the loop body without spinning."""
        return SymbolicInductionAnalyzer.evaluate_symbolic_pass(
            body,
            summary,
            memory_provider=self.memory_provider
        )

    def _extract_ops(self, body: List[Any], state_0: AbstractState) -> None:
        """Extracts and initializes registers and memory locations accessed in the loop body."""
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
                        if op.get('type') == 'mem':
                            size = op.get('size', 4) * 8
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

    def _run_pass(self, body: List[Any], state: AbstractState) -> AbstractState:
        """Executes a single abstract interpretation pass over the body."""
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

    def evaluate(self, loop_block: LoopBlock) -> LoopSummary:
        """
        Main entrypoint: evaluates the symbolic and bounded abstract state of a loop block.
        """
        # Fast path: return an isolated copy of pre-computed mathematical summary
        if getattr(loop_block, '_cached_summary', None) is not None:
            return copy.copy(loop_block._cached_summary)

        summary = LoopSummary()

        # Step 1: Execute Single-Pass Symbolic Induction (Zero-Spinning O(1))
        self._evaluate_symbolic_pass(loop_block.body, summary)

        # Step 2: Extract Polycyclic Patterns and Abstract State verification
        state_0 = AbstractState()
        self._extract_ops(loop_block.body, state_0)
            
        K = getattr(self, 'k_passes', 100)
        passes = [state_0]
        for _ in range(K):
            next_state = self._run_pass(loop_block.body, passes[-1])
            passes.append(next_state)
        
        all_tracked = set()
        for st in passes:
            all_tracked.update(st.registers.keys())
            
        def to_signed(val: int, bit_width: int = 64) -> int:
            mask = (1 << bit_width) - 1
            v = val & mask
            if v >= (1 << (bit_width - 1)):
                return v - (1 << bit_width)
            return v
            
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
            if all(v == v0 for v in values):
                continue
                
            if all(v == values[1] for v in values[1:]):
                summary.constant_sets[reg_name] = values[1]
                continue
                
            step_deltas = [to_signed(values[i] - values[i - 1]) for i in range(1, len(values))]
            
            if all(d == step_deltas[0] for d in step_deltas):
                summary.deltas[reg_name] = step_deltas[0]
                continue
                
            # Polycyclic Stride Pattern (P >= 2)
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

        # Step 3: Discover child inner loops recursively
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

        # Step 4: Delegate ALL control flow and condition analysis to the tracking facade
        cond_str, exit_records = TrackerBridge.evaluate_loop_exit(loop_block, induction_vars=set(summary.deltas.keys()))
        if cond_str:
            summary.exit_condition = cond_str
            summary.exit_records = exit_records
                
        summary.iterations = loop_block.iterations
        loop_block._cached_summary = summary
        return copy.copy(summary)
