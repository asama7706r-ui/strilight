from typing import List, Union
from asm_analyzer.engine.tracker import TraceRecord

class LoopBlock:
    """
    Represents a compressed block of TraceRecords that repeats multiple times.
    Phase 1: Tagging and Structural Compression.
    
    ================================================================================
    TODO / FUTURE ARCHITECTURE ROADMAP: Fixing Structural Loop Flaws
    ================================================================================
    1. Partial Final-Iteration Execution (The Off-By-One Flaw):
       Currently, we assume the loop exits strictly at the end of the block.
       Future Fix: We must build a flexible positional tracking mechanism to compute
       the exact index of the exit instruction. Operations occurring *after* the
       exit instruction should be bypassed (not evaluated) during the final (N-th)
       iteration to ensure mathematical precision for Mid-Condition loops.
       
    2. Compound & Correlated Exit Conditions (Short-circuiting Flaws):
       If a loop has multiple exit paths or complex AND/OR logic, translating only 
       the final exit condition is insufficient.
       Future Fix: We must translate Loop Invariants ensuring no early exits were 
       triggered during iterations 0 to N-1. The Z3 translation layer must be 
       upgraded to model these correlated conditions to prevent Z3 from inferring 
       false early exits.
    ================================================================================
    """
    def __init__(self, body: List[Union[TraceRecord, 'LoopBlock']], iterations: int):
        self.body = body
        self.iterations = iterations
        self.start_tick = self._get_first_tick(body)
        self.end_tick = self._get_last_tick(body)
        
    def _get_first_tick(self, body):
        if not body: return -1
        first = body[0]
        if isinstance(first, TraceRecord): return first.tick
        return first.start_tick

    def _get_last_tick(self, body):
        if not body: return -1
        last = body[-1]
        if isinstance(last, TraceRecord): return last.tick
        return last.end_tick

    def __repr__(self):
        body_len = len(self.body)
        return f"<LoopBlock Iters:{self.iterations} Size:{body_len} Ticks:{self.start_tick}->{self.end_tick}>"


class TraceCompressor:
    """
    Scans a raw execution trace and compresses repetitive patterns into LoopBlocks.
    This acts as Phase 1 (Lazy Tagging) to prevent State Explosion in the Tracker.
    """
    
    @classmethod
    def _hash_record(cls, record: Union[TraceRecord, 'LoopBlock']) -> int:
        # We identify a matching instruction by its address.
        # For a LoopBlock, we hash its structural signature (body and iterations).
        if hasattr(record, 'body'):
            body_hashes = tuple(cls._hash_record(r) for r in record.body)
            return hash(("LoopBlock", getattr(record, 'iterations', 0), body_hashes))
        return getattr(record, 'address', 0)

    @classmethod
    def compress_trace(cls, trace: List[Union[TraceRecord, 'LoopBlock']], min_iterations: int = 3) -> List[Union[TraceRecord, 'LoopBlock']]:
        """
        Compresses the trace by folding contiguous repeating sequences.
        Operates hierarchically (bottom-up) to compress nested loops.
        """
        if not trace:
            return []
            
        current_trace = trace
        while True:
            new_trace = cls._compress_pass(current_trace, min_iterations)
            if len(new_trace) == len(current_trace):
                break
            current_trace = new_trace
            
        return current_trace

    @classmethod
    def _compress_pass(cls, trace: List[Union[TraceRecord, 'LoopBlock']], min_iterations: int) -> List[Union[TraceRecord, 'LoopBlock']]:
        # Convert to an array of hashes for fast comparison
        hashed_trace = [cls._hash_record(r) for r in trace]
        n = len(trace)
        
        compressed = []
        i = 0
        
        while i < n:
            best_pattern_size = 0
            best_iterations = 0
            
            # Optimization: We only check pattern sizes up to a certain limit or half the remaining trace
            max_pattern_size = min(5000, (n - i) // min_iterations)
            
            for pattern_size in range(1, max_pattern_size + 1):
                # Try to see how many times the pattern of `pattern_size` repeats
                iterations = 1
                while i + (iterations + 1) * pattern_size <= n:
                    # Compare the current block with the next block
                    current_block_start = i + (iterations - 1) * pattern_size
                    next_block_start = i + iterations * pattern_size
                    
                    match = True
                    for j in range(pattern_size):
                        if hashed_trace[current_block_start + j] != hashed_trace[next_block_start + j]:
                            match = False
                            break
                            
                    if match:
                        iterations += 1
                    else:
                        break
                        
                if iterations >= min_iterations and iterations > best_iterations:
                    best_iterations = iterations
                    best_pattern_size = pattern_size
            
            if best_iterations >= min_iterations:
                # We found a loop!
                loop_body = trace[i : i + best_pattern_size]
                compressed_body = cls.compress_trace(loop_body, min_iterations)
                compressed_block = LoopBlock(body=compressed_body, iterations=best_iterations)
                compressed.append(compressed_block)
                
                # Advance pointer
                i += best_iterations * best_pattern_size
            else:
                # No loop found starting at this instruction, add it raw
                compressed.append(trace[i])
                i += 1
                
        return compressed
