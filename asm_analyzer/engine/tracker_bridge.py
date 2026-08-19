from typing import List, Set, Union, Optional
import copy
from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import LoopBlock
from asm_analyzer.engine.x86_defs import get_flags_written, get_instruction_type, get_flags_read
from typing import Tuple

_REG_TO_BASE = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
    'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
    'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
    'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
    'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
    'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
    'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
    'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
}

_BASE_TO_REGS = {}
for _sub, _base in _REG_TO_BASE.items():
    _BASE_TO_REGS.setdefault(_base, set()).add(_sub)

class TrackerBridge:
    """
    Facade layer to decouple instruction tracking logic from the VSA Evaluator.
    Provides generic helper functions for extracting instruction dependencies.
    """
    
    @staticmethod
    def get_intra_block_slice(
        body: List[Union[TraceRecord, LoopBlock]], 
        start_idx: int, 
        targets: Set[str],
        induction_vars: Set[str] = set()
    ) -> List[TraceRecord]:
        """
        Performs a lazy, intra-block backward slice to find the instructions 
        that satisfy the required targets (e.g., flags).
        
        Args:
            body: The sequence of instructions/blocks (e.g., loop_block.body)
            start_idx: The index to start searching backward from (exclusive).
            targets: A set of target variable/flag names to find writers for.
            induction_vars: Induction variables of the loop whose self-updates are already captured by loop deltas.
            
        Returns:
            A list of TraceRecords that generate the requested targets.
            The list is in chronological order.
        """
        needed_targets = set(targets)
        slice_records = []
        ignored_regs = {'rsp', 'esp', 'sp', 'spl', 'rbp', 'ebp', 'bp', 'bpl', 'rip'}
        
        # Expand induction_vars with register aliases
        expanded_induction = set()
        for v in induction_vars:
            base = _REG_TO_BASE.get(v, v)
            expanded_induction.update(_BASE_TO_REGS.get(base, {v}))
        
        # Backward search
        for i in range(start_idx - 1, -1, -1):
            if not needed_targets:
                break # Lazy Evaluation: Stop when all targets are satisfied
                
            item = body[i]
            
            # Handle Nested Loops gracefully to prevent the "Nested Loop Block" crash
            if isinstance(item, LoopBlock):
                continue
                
            if isinstance(item, TraceRecord):
                # Does this instruction write to any of our needed targets?
                written_explicit = set()
                for r in item.regs_write:
                    base = _REG_TO_BASE.get(r, r)
                    written_explicit.update(_BASE_TO_REGS.get(base, {r}))
                    
                written_meta = set(get_flags_written(item.mnemonic))
                all_written = written_explicit.union(written_meta)
                
                # Intersection to find if it satisfies any need
                satisfied = needed_targets.intersection(all_written)
                
                # Filter out self-updating induction steps ONLY for genuine loop induction variables
                # (e.g. inc ecx in loops where ecx is an induction variable with a delta)
                reg_satisfied = {r for r in satisfied if not r.startswith('flag_')}
                induction_satisfied = {r for r in reg_satisfied if r in expanded_induction or _REG_TO_BASE.get(r, r) in expanded_induction}
                if induction_satisfied and any(_REG_TO_BASE.get(r, r) in [_REG_TO_BASE.get(rr, rr) for rr in item.regs_read] for r in induction_satisfied):
                    for sat_target in induction_satisfied:
                        needed_targets.discard(sat_target)
                        base = _REG_TO_BASE.get(sat_target, sat_target)
                        if base in _BASE_TO_REGS:
                            needed_targets -= _BASE_TO_REGS[base]
                    satisfied = {s for s in satisfied if s not in induction_satisfied}
                
                if satisfied:
                    record_copy = copy.copy(item)
                    if not hasattr(record_copy, 'requested_flags'):
                        record_copy.requested_flags = []
                        
                    for flag in satisfied:
                        if flag.startswith('flag_') and flag not in record_copy.requested_flags:
                            record_copy.requested_flags.append(flag)
                            
                    slice_records.append(record_copy)
                    
                    # Remove found targets (and their subregister family)
                    for sat_target in satisfied:
                        needed_targets.discard(sat_target)
                        base = _REG_TO_BASE.get(sat_target, sat_target)
                        if base in _BASE_TO_REGS:
                            needed_targets -= _BASE_TO_REGS[base]
                            
                    # Def-Use chain: track registers read by this defining instruction
                    for r in getattr(item, 'regs_read', []):
                        base = _REG_TO_BASE.get(r, r)
                        if base not in ignored_regs and r not in ignored_regs and base not in expanded_induction:
                            needed_targets.add(r)

        # Reverse to return them in chronological execution order
        slice_records.reverse()
        return slice_records

    @staticmethod
    def evaluate_loop_exit(loop_block: LoopBlock, induction_vars: Set[str] = set()) -> Tuple[Optional[str], List[TraceRecord]]:
        """
        Encapsulates all control-flow logic for finding and resolving 
        the loop's exit condition.
        
        Returns:
            A tuple of (formatted_condition_string, list_of_exit_records)
        """
        cond_strings = []
        all_exit_records = []
        
        # 1. Find ALL conditional jumps in the loop body
        # This handles loops with multiple conditions (e.g., mid-loop 'break' and a 'while' condition)
        for i in range(len(loop_block.body)):
            item = loop_block.body[i]
            if not hasattr(item, 'mnemonic'):
                continue
                
            if get_instruction_type(item.mnemonic) == 'jcc':
                exit_jmp = copy.copy(item)
                
                # 2. Extract dependencies via lazy backward slice for THIS specific jump
                flags_needed = set(get_flags_read(exit_jmp.mnemonic))
                slice_records = TrackerBridge.get_intra_block_slice(loop_block.body, i, flags_needed, induction_vars=induction_vars)
                
                # 3. Determine control flow behavior (was jump taken or not?) and filter intra-loop branches
                try:
                    target_addr = int(exit_jmp.op_str, 16)
                    def _get_all_addresses(body):
                        addrs = set()
                        for r in body:
                            if hasattr(r, 'iterations') and hasattr(r, 'body'):
                                addrs.update(_get_all_addresses(r.body))
                            elif hasattr(r, 'address'):
                                addrs.add(r.address)
                        return addrs
                        
                    loop_addresses = _get_all_addresses(loop_block.body)
                    
                    if target_addr not in loop_addresses:
                        # Case 1: Jumps OUTSIDE the loop. Exiting means this jump MUST be taken.
                        exit_jmp.jump_taken = True
                    elif hasattr(exit_jmp, 'address') and target_addr <= exit_jmp.address:
                        # Case 2: Jumps BACKWARDS (back-edge) inside the loop.
                        # The true back-edge of a loop jumps to its header, which is the 
                        # lowest memory address of the loop's block.
                        # If a backward jump targets an address greater than the minimum address,
                        # it must be the back-edge of an INNER nested loop!
                        if loop_addresses:
                            min_addr = min(loop_addresses)
                            print(f"[DEBUG TRACKER_BRIDGE] JMP BACKWARD: {exit_jmp.mnemonic} to {hex(target_addr)}. Min addr is {hex(min_addr)}")
                            if target_addr > min_addr:
                                print(f"[DEBUG TRACKER_BRIDGE] -> IGNORED (target {hex(target_addr)} > min {hex(min_addr)})")
                                continue
                            print(f"[DEBUG TRACKER_BRIDGE] -> ACCEPTED as back-edge!")
                        exit_jmp.jump_taken = False
                    else:
                        # Case 3: Jumps FORWARDS inside the loop (e.g. an internal if-statement). 
                        # This is an intra-loop branch, not an exit condition! We ignore it.
                        print(f"[DEBUG TRACKER_BRIDGE] JMP FORWARD: {exit_jmp.mnemonic} to {hex(target_addr)} (Ignored)")
                        continue
                        
                except ValueError:
                    pass # Fallback if op_str is weird
                    
                # 4. Format a human-readable condition string
                cond_str = " & ".join([f"{r.mnemonic} {r.op_str}" for r in slice_records])
                formatted_condition = f"[{cond_str}] -> {exit_jmp.mnemonic}(Taken:{exit_jmp.jump_taken})"
                print(f"[DEBUG TRACKER_BRIDGE] Found Exit Condition: {formatted_condition}")
                
                cond_strings.append(formatted_condition)
                all_exit_records.extend(slice_records)
                all_exit_records.append(exit_jmp)
                
        if not cond_strings:
            return None, []
            
        # Return cleanly to the math evaluator
        return " AND ".join(cond_strings), all_exit_records
