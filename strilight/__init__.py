"""
Strilight: High-Performance O(1) SMT Loop Lifting & Strided Interval Domain
============================================================================
A lightweight, high-performance abstract interpretation and symbolic loop-lifting library for x86_64 binaries.
"""

from typing import List, Union, Optional

__version__ = "0.1.0"

# Core abstractions
from strilight.engine.instruction import Instruction
from strilight.engine.loop_compressor import LoopBlock, TraceCompressor
from strilight.engine.vsa_evaluator import LoopEvaluator, LoopSummary, LoopInvariantContract
from strilight.engine.tracker_bridge import TrackerBridge
from strilight.pruning.interval import Interval, StridedInterval, DisjointIntervalSet

# Optional modules (imported safely)
try:
    from strilight.engine.tracker import Tracker, TraceRecord, BackwardTracker
except ImportError:
    pass

try:
    from strilight.engine.translator import Z3Translator
except ImportError:
    pass


# =============================================================================
# High-Level Facade API (Instant Developer Experience)
# =============================================================================

def disassemble(code_bytes: bytes, base_address: int = 0x1000, bit_mode: int = 64) -> List[Instruction]:
    """
    Disassembles raw machine code bytes into standard Instruction objects.
    """
    return Instruction.disassemble_bytes(code_bytes, base_address=base_address, bit_mode=bit_mode)


def compress(trace: List[Union[Instruction, LoopBlock]], min_iterations: int = 3) -> List[Union[Instruction, LoopBlock]]:
    """
    Compresses repeated instruction execution traces into LoopBlock hierarchies.
    """
    return TraceCompressor.compress_trace(trace, min_iterations=min_iterations)


def evaluate(block_or_trace: Union[LoopBlock, List[Instruction]], k_passes: int = 100, iterations: int = 1000) -> LoopSummary:
    """
    Evaluates abstract strided intervals and generates the closed-form loop invariant contract.
    """
    if isinstance(block_or_trace, list):
        block_or_trace = LoopBlock(body=block_or_trace, iterations=iterations)
    evaluator = LoopEvaluator(k_passes=k_passes)
    return evaluator.evaluate(block_or_trace)


def analyze(code_bytes: bytes, iterations: int = 1000, base_address: int = 0x1000, bit_mode: int = 64, k_passes: int = 100) -> LoopSummary:
    """
    One-line end-to-end loop analysis:
    Disassembles machine code bytes, wraps into a LoopBlock, and extracts closed-form deltas & invariant contracts.
    """
    instructions = disassemble(code_bytes, base_address=base_address, bit_mode=bit_mode)
    block = LoopBlock(body=instructions, iterations=iterations)
    return evaluate(block, k_passes=k_passes)


__all__ = [
    # High-Level Facade Functions
    "disassemble",
    "compress",
    "evaluate",
    "analyze",
    
    # Core Classes
    "Instruction",
    "LoopBlock",
    "TraceCompressor",
    "LoopEvaluator",
    "LoopSummary",
    "LoopInvariantContract",
    "TrackerBridge",
    "Interval",
    "StridedInterval",
    "DisjointIntervalSet",
]
