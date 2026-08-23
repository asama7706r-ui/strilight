"""
Strided Loop Compressor & SMT Lifting Engine
============================================
A high-performance abstract interpretation and symbolic loop-lifting library for x86_64 binaries.
"""

__version__ = "0.1.0"

# Core abstractions
from asm_analyzer.engine.instruction import Instruction
from asm_analyzer.engine.loop_compressor import LoopBlock, TraceCompressor
from asm_analyzer.engine.vsa_evaluator import LoopEvaluator, LoopSummary
from asm_analyzer.engine.tracker_bridge import TrackerBridge
from asm_analyzer.pruning.interval import Interval, StridedInterval, DisjointIntervalSet

# Optional modules (imported safely)
try:
    from asm_analyzer.engine.tracker import Tracker, TraceRecord, BackwardTracker
except ImportError:
    pass

try:
    from asm_analyzer.engine.translator import Z3Translator
except ImportError:
    pass

__all__ = [
    "Instruction",
    "LoopBlock",
    "TraceCompressor",
    "LoopEvaluator",
    "LoopSummary",
    "TrackerBridge",
    "Interval",
    "StridedInterval",
    "DisjointIntervalSet",
]
