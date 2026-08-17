import copy
from typing import Dict, Optional, List, TYPE_CHECKING
if TYPE_CHECKING:
    from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.abstract_state import AbstractState
from asm_analyzer.pruning.interval import Interval, DisjointIntervalSet
from asm_analyzer.engine.loop_compressor import LoopBlock

class LoopSummary:
    """
    Symbolic mathematical summary of a loop's effect.
    This is passed to the BackwardTracker (or Translator) to instantly jump over the loop.
    """
    def __init__(self):
        # Maps register name to its extracted symbolic delta per iteration (e.g., EAX increases by 4)
        self.deltas: Dict[str, int] = {}
        
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
    using Value Set Analysis (VSA) bounds to extract strides (deltas). 
    It NEVER reads conditional flags (ZF, CF) and NEVER executes control-flow instructions (jcc).
    Conditional loop-exit instructions are simply bundled into `summary.exit_records` and handed 
    over to `Z3Translator` for actual mathematical control-flow translation.
    """
    def __init__(self):
        pass
        
    def evaluate(self, loop_block: LoopBlock) -> LoopSummary:
        # Initial Blank Slate
        state_0 = AbstractState()
        
        # Pre-initialize registers and active memory to Symbolic Zero [0, 0] to extract relative Deltas
        for record in loop_block.body:
            for is_dst, ops in [(False, record.regs_read), (True, record.regs_write)]:
                for reg in ops:
                    if reg not in state_0.registers:
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, 0))
                        state_0.set_register(reg, dset)
            
            for is_dst, mems in [(False, record.mem_read), (True, record.mem_write)]:
                for mem in mems:
                    size = record.size * 8 if hasattr(record, 'size') else 32
                    for op in record.operands:
                        if op['type'] == 'mem': size = op.get('size', 4) * 8
                    key = f"MEM_{mem}_{size}"
                    if key not in state_0.registers:
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, 0))
                        state_0.set_register(key, dset)
            
        # Pass 1: Run the macro-block once
        state_1 = self._run_pass(loop_block.body, state_0)
        
        # Pass 2: Run the macro-block twice
        state_2 = self._run_pass(loop_block.body, state_1)
        
        summary = LoopSummary()
        
        # TODO: Polycyclic Stride Patterns (الأنماط الدورية لمعامل الخطوة)
        # =========================================================================
        # Architectural Note from Client Session:
        # Currently, the engine only extracts a single scalar Delta (Affine Loops).
        # If a variable increments in a pattern (e.g. +5, +4, +8, +1), the VSA will 
        # fail to extract a constant delta here, throwing the loop to a symbolic fallback.
        # 
        # Future Upgrade Path:
        # Instead of just diffing Pass 2 and Pass 1, we can run Pass 1..P to find 
        # a repeating pattern of length P (e.g., [5, 4, 8, 1]).
        # If found, Z3 can translate this natively without unrolling using:
        # FullCycles = N / P
        # Base_Delta = FullCycles * Sum(Pattern)
        # Remainder = N % P
        # Extra_Delta = If(Remainder == 1, P[0], If(Remainder == 2, P[0]+P[1], ...))
        # Reg_new = Reg_old + Base_Delta + Extra_Delta
        # 
        # This keeps the O(1) compression magic even for highly obfuscated loops!
        # =========================================================================
        
        # TODO: Multithreading & Symbolic Temporal Dimension (معضلة الزمن الرمزي في الخيوط المتوازية)
        # =========================================================================
        # Architectural Dilemma:
        # Currently, the engine compresses loops into a flat temporal space. But if we support 
        # multithreading, this breaks. If Thread B reads a memory address modified by Thread A 
        # *during* Thread A's loop, the exact 'Tick' matters. 
        # However, the number of iterations (N) is SYMBOLIC (depends on user input). 
        # If N is symbolic, the duration of the loop is symbolic (Duration = N * Body_Size).
        # This makes the 'Tick' of EVERY instruction *after* the loop symbolic too!
        # We cannot simply use VSA intervals for time, because establishing happens-before 
        # relationships (Tick_A < Tick_B) across threads with symbolic time causes an OOM/Bit-blasting 
        # explosion in Z3 due to the quadratic number of conditional memory aliases.
        #
        # Ideal Solution (Theoretical):
        # Do not use absolute ticks for concurrent memory resolution. Instead, use 
        # "Relational Partial Ordering" (Lamport Clocks combined with Memory Versioning). 
        # The engine must only emit a constraint: `If Thread_B_Read_Val == Thread_A_Loop_Val(k)` 
        # `Then Require: Tick_B == Tick_A_LoopStart + k * Body_Size`. 
        # This shifts the burden from "resolving time to find data" to "assuming data to constraint time".
        # However, until fully proven, this remains a profound architectural dilemma.
        # =========================================================================
        
        # Extract Strides (Deltas) by comparing Pass 2 with Pass 1
        for reg_name in state_1.registers:
            dset_1 = state_1.registers[reg_name]
            dset_2 = state_2.registers[reg_name]
            
            if len(dset_1.intervals) == 1 and len(dset_2.intervals) == 1:
                i1 = dset_1.intervals[0]
                i2 = dset_2.intervals[0]
                
                # If they are concrete/stable points, we can safely extract delta
                if i1.min_val == i1.max_val and i2.min_val == i2.max_val:
                    if i1.min_val == i2.min_val:
                        # Value didn't change between loops.
                        # Check if it's genuinely a constant set inside the loop, or just UNMODIFIED.
                        dset_0 = state_0.registers.get(reg_name)
                        if dset_0 and len(dset_0.intervals) == 1 and dset_0.intervals[0].min_val == i1.min_val:
                            # It's identical to state_0 (which was artificially 0). It's UNMODIFIED.
                            pass
                        else:
                            # It changed from state_0 to state_1, but stayed the same in state_2 -> Constant Set
                            summary.constant_sets[reg_name] = i1.min_val
                    else:
                        # Value changed -> Extract the Delta (Stride)
                        delta = i2.min_val - i1.min_val
                        summary.deltas[reg_name] = delta
                        print(f"  [LoopEvaluator] Extracted Delta for {reg_name}: {delta}")
                        
        # Extract Exit Condition from the end of the block
        if len(loop_block.body) >= 2:
            last_inst = loop_block.body[-1]
        # Search for the exit condition (CMP/TEST followed by JCC) anywhere in the loop body
        exit_cmp = None
        exit_jmp = None
        for i in range(1, len(loop_block.body)):
            curr_inst = loop_block.body[i]
            prev_inst = loop_block.body[i-1]
            if curr_inst.mnemonic.startswith("j") and curr_inst.mnemonic != "jmp" and prev_inst.mnemonic in ["cmp", "test"]:
                exit_cmp = copy.copy(prev_inst)
                exit_jmp = copy.copy(curr_inst)
                summary.exit_condition = f"{prev_inst.mnemonic} {prev_inst.op_str} -> {curr_inst.mnemonic}"
                break
                
        if exit_cmp and exit_jmp:
            # Force the CMP to generate all relevant flags for the JMP (ZF, SF, OF, CF)
            if not hasattr(exit_cmp, 'requested_flags'):
                exit_cmp.requested_flags = []
            for flag in ['flag_zf', 'flag_cf', 'flag_sf', 'flag_of']:
                if flag not in exit_cmp.requested_flags:
                    exit_cmp.requested_flags.append(flag)
            
            # Determine if the jump is taken or not when exiting the loop
            try:
                target_addr = int(exit_jmp.op_str, 16)
                loop_addresses = {r.address for r in loop_block.body if hasattr(r, 'address')}
                if target_addr in loop_addresses:
                    # Jump goes back into the loop. Exiting means it was NOT taken.
                    exit_jmp.jump_taken = False
                else:
                    # Jump goes outside the loop. Exiting means it WAS taken.
                    exit_jmp.jump_taken = True
            except ValueError:
                # Fallback if op_str is not an explicit address
                exit_jmp.jump_taken = False
                
            summary.exit_records = [exit_cmp, exit_jmp]
                
        summary.iterations = loop_block.iterations
        return summary

    def _run_pass(self, body, state: AbstractState) -> AbstractState:
        # Deepcopy the state to isolate iterations
        new_state = copy.deepcopy(state)
        
        for record in body:
            self._dispatch_instruction(record, new_state)
            
        return new_state
        
    def _dispatch_instruction(self, record, state: AbstractState):
        """
        Instruction Dispatcher. Maps x86 instructions to VSA Mathematical Primitives.
        """
        mnemonic = record.mnemonic.lower()
        op_str = record.op_str
        
        # Basic Operand Parser utilizing TraceRecord attributes
        def get_op_key(op, is_dest=False):
            if op['type'] == 'reg':
                return op['value']
            elif op['type'] == 'mem':
                addr_list = record.mem_write if is_dest else record.mem_read
                if addr_list:
                    addr = addr_list[0]
                    size = op.get('size', 4) * 8
                    return f"MEM_{addr}_{size}"
            return None

        if mnemonic == "add" and len(record.operands) == 2:
            dest = get_op_key(record.operands[0], is_dest=True)
            if not dest: return
            src_op = record.operands[1]
            dest_dset = state.get_register(dest)
            
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
                
        elif mnemonic == "sub" and len(record.operands) == 2:
            dest = get_op_key(record.operands[0], is_dest=True)
            if not dest: return
            src_op = record.operands[1]
            dest_dset = state.get_register(dest)
            
            if src_op['type'] == 'imm':
                val = src_op['value']
                src_int = Interval(val, val)
                
                new_dset = DisjointIntervalSet(k_limit=8)
                for i in dest_dset.intervals:
                    res = i.sub(src_int)
                    for r in res.intervals:
                        new_dset.add(r)
                state.set_register(dest, new_dset)
                
        elif mnemonic == "mov" and len(record.operands) == 2:
            dest = get_op_key(record.operands[0], is_dest=True)
            if not dest: return
            src_op = record.operands[1]
            
            if src_op['type'] == 'imm':
                val = src_op['value']
                new_dset = DisjointIntervalSet(k_limit=8)
                new_dset.add(Interval(val, val))
                state.set_register(dest, new_dset)
            elif src_op['type'] == 'reg' or src_op['type'] == 'mem':
                src = get_op_key(src_op, is_dest=False)
                if src:
                    src_dset = state.get_register(src)
                    state.set_register(dest, copy.deepcopy(src_dset))

        elif mnemonic == "inc" and len(record.operands) == 1:
            dest = get_op_key(record.operands[0], is_dest=True)
            if not dest: return
            dest_dset = state.get_register(dest)
            src_int = Interval(1, 1)
            new_dset = DisjointIntervalSet(k_limit=8)
            for i in dest_dset.intervals:
                res = i.add(src_int)
                for r in res.intervals:
                    new_dset.add(r)
            state.set_register(dest, new_dset)

        elif mnemonic == "dec" and len(record.operands) == 1:
            dest = get_op_key(record.operands[0], is_dest=True)
            if not dest: return
            dest_dset = state.get_register(dest)
            src_int = Interval(1, 1)
            new_dset = DisjointIntervalSet(k_limit=8)
            for i in dest_dset.intervals:
                res = i.sub(src_int)
                for r in res.intervals:
                    new_dset.add(r)
            state.set_register(dest, new_dset)
