import logging
from typing import List, Set, Union, Optional, Any, Tuple, TYPE_CHECKING
import copy
from strilight.engine.loop_compressor import LoopBlock
from strilight.engine.x86_defs import (
    get_flags_written,
    get_instruction_type,
    get_flags_read,
    REG_TO_BASE,
    BASE_TO_REGS
)
if TYPE_CHECKING:
    from strilight.engine.tracker import TraceRecord

logger = logging.getLogger("strilight.engine.tracker_bridge")

class TrackerBridge:
    """
    Default Embedded Intra-Block Tracer & Condition Resolver.
    Decouples instruction tracking logic from the VSA Evaluator.
    Supports optional external custom tracers.
    """
    custom_tracer: Optional[Any] = None

    @classmethod
    def register_tracer(cls, tracer: Any):
        """Allows users to plug in a custom external tracer engine (e.g. Frida, Ghidra, angr)."""
        cls.custom_tracer = tracer

    @staticmethod
    def get_intra_block_slice(
        body: List[Union[Any, LoopBlock]], 
        start_idx: int, 
        targets: Set[str],
        induction_vars: Set[str] = set()
    ) -> List[Any]:
        """
        Performs a lazy, intra-block backward slice to find the instructions 
        that satisfy the required targets (e.g., flags).
        """
        needed_targets = set(targets)
        slice_records = []
        ignored_regs = {'rsp', 'esp', 'sp', 'spl', 'rbp', 'ebp', 'bp', 'bpl', 'rip'}
        
        # Expand induction_vars with register aliases
        expanded_induction = set()
        for v in induction_vars:
            base = REG_TO_BASE.get(v, v)
            expanded_induction.update(BASE_TO_REGS.get(base, {v}))
        
        # Backward search
        for i in range(start_idx - 1, -1, -1):
            if not needed_targets:
                break # Lazy Evaluation: Stop when all targets are satisfied
                
            item = body[i]
            
            # Handle Nested Loops gracefully
            if hasattr(item, 'body'):
                continue
                
            if hasattr(item, 'mnemonic'):
                # Does this instruction write to any of our needed targets?
                written_explicit = set()
                for r in getattr(item, 'regs_write', []):
                    base = REG_TO_BASE.get(r, r)
                    written_explicit.update(BASE_TO_REGS.get(base, {r}))
                    
                written_meta = set(get_flags_written(item.mnemonic))
                all_written = written_explicit.union(written_meta)
                
                # Intersection to find if it satisfies any need
                satisfied = needed_targets.intersection(all_written)
                
                # Filter out self-updating induction steps ONLY for genuine loop induction variables
                # (e.g. inc ecx in loops where ecx is an induction variable with a delta)
                reg_satisfied = {r for r in satisfied if not r.startswith('flag_')}
                induction_satisfied = {r for r in reg_satisfied if r in expanded_induction or REG_TO_BASE.get(r, r) in expanded_induction}
                if induction_satisfied and any(REG_TO_BASE.get(r, r) in [REG_TO_BASE.get(rr, rr) for rr in item.regs_read] for r in induction_satisfied):
                    for sat_target in induction_satisfied:
                        needed_targets.discard(sat_target)
                        base = REG_TO_BASE.get(sat_target, sat_target)
                        if base in BASE_TO_REGS:
                            needed_targets -= BASE_TO_REGS[base]
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
                        base = REG_TO_BASE.get(sat_target, sat_target)
                        if base in BASE_TO_REGS:
                            needed_targets -= BASE_TO_REGS[base]
                            
                    # Def-Use chain: track registers read by this defining instruction
                    for r in getattr(item, 'regs_read', []):
                        base = REG_TO_BASE.get(r, r)
                        if base not in ignored_regs and r not in ignored_regs and base not in expanded_induction:
                            needed_targets.add(r)

        # Reverse to return them in chronological execution order
        slice_records.reverse()
        return slice_records

    @classmethod
    def evaluate_loop_exit(cls, loop_block: LoopBlock, induction_vars: Set[str] = set()) -> Tuple[Optional[str], List[Any]]:
        """
        Encapsulates all control-flow logic for finding and resolving 
        the loop's exit condition.
        Delegates to custom_tracer if registered, otherwise runs Default Intra-Block Slicer.
        
        Returns:
            A tuple of (formatted_condition_string, list_of_exit_records)
        """
        if cls.custom_tracer is not None and hasattr(cls.custom_tracer, 'evaluate_loop_exit'):
            return cls.custom_tracer.evaluate_loop_exit(loop_block, induction_vars)

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
                            logger.debug("JMP BACKWARD: %s to %s. Min addr is %s", exit_jmp.mnemonic, hex(target_addr), hex(min_addr))
                            if target_addr > min_addr:
                                logger.debug("-> IGNORED (target %s > min %s)", hex(target_addr), hex(min_addr))
                                continue
                            logger.debug("-> ACCEPTED as back-edge!")
                        exit_jmp.jump_taken = False
                    else:
                        # Case 3: Jumps FORWARDS inside the loop (e.g. an internal if-statement). 
                        # This is an intra-loop branch, not an exit condition! We ignore it.
                        logger.debug("JMP FORWARD: %s to %s (Ignored)", exit_jmp.mnemonic, hex(target_addr))
                        continue
                        
                except ValueError:
                    pass # Fallback if op_str is weird
                    
                # 4. Format a human-readable condition string
                cond_str = " & ".join([f"{r.mnemonic} {r.op_str}" for r in slice_records])
                formatted_condition = f"[{cond_str}] -> {exit_jmp.mnemonic}(Taken:{exit_jmp.jump_taken})"
                logger.debug("Found Exit Condition: %s", formatted_condition)
                
                cond_strings.append(formatted_condition)
                all_exit_records.extend(slice_records)
                all_exit_records.append(exit_jmp)
                
        if not cond_strings:
            return None, []
            
        # Return cleanly to the math evaluator
        return " AND ".join(cond_strings), all_exit_records
