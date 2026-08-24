"""
Strilight Engine Subpackage
===========================
Provides core binary analysis, loop compression, abstract interpretation,
SSA translation, and backward/forward slice tracking.
"""

from strilight.engine.instruction import Instruction
from strilight.engine.loop_compressor import LoopBlock, TraceCompressor
from strilight.engine.vsa_evaluator import LoopEvaluator, LoopSummary, LoopInvariantContract
from strilight.engine.tracker_bridge import TrackerBridge
from strilight.engine.abstract_state import AbstractState
from strilight.engine.path_tree import PathTree, PathNode

# Optional / Heavy dependencies (imported safely)
try:
    from strilight.engine.tracker import (
        Tracker,
        TraceRecord,
        BackwardTracker,
        BackwardSliceTracker,
        ForwardSliceTracker,
        Descendant,
        Ancestor
    )
except ImportError:
    pass

try:
    from strilight.engine.translator import Z3Translator
except ImportError:
    pass


def __getattr__(name: str):
    """
    Lazy load optional / heavy backend modules (PEP 562) to prevent
    unintended eager emulation overhead and enable clean mocking in unit tests.
    """
    if name == "AnalyzerCore":
        from strilight.engine.core import AnalyzerCore
        return AnalyzerCore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Disassembly & Representation
    "Instruction",
    
    # Loop Folding & Compression
    "LoopBlock",
    "TraceCompressor",
    
    # Abstract Interpretation (VSA) & Contracts
    "LoopEvaluator",
    "LoopSummary",
    "LoopInvariantContract",
    "AbstractState",
    
    # Bridge & Path Trees
    "TrackerBridge",
    "PathTree",
    "PathNode",
    
    # Slicing & Tracking (Optional)
    "Tracker",
    "TraceRecord",
    "BackwardTracker",
    "BackwardSliceTracker",
    "ForwardSliceTracker",
    "Descendant",
    "Ancestor",
    
    # SMT Translation (Optional)
    "Z3Translator",
    
    # Emulation Backend Core (Lazy-loaded)
    "AnalyzerCore",
]
