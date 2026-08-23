"""
Strided Loop Compressor & SMT Lifting Engine
============================================
A high-performance abstract interpretation and symbolic loop-lifting library for x86_64 binaries.
"""

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

__all__ = [
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
