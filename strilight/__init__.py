"""
Strilight: High-Performance O(1) SMT Loop Lifting & Strided Interval Domain
============================================================================
A lightweight, high-performance abstract interpretation and symbolic loop-lifting library for x86_64 binaries.
"""

import logging
import sys
from typing import List, Union, Optional

__version__ = "0.2.0"

# Module-level logger with default NullHandler (zero unwanted stdout noise when imported)
logger = logging.getLogger("strilight")
logger.addHandler(logging.NullHandler())


def set_log_level(level: Union[int, str]):
    """
    Sets the logging level for the strilight root logger.
    Example: sl.set_log_level(logging.DEBUG) or sl.set_log_level("INFO")
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(level)


def enable_logging(level: Union[int, str] = logging.INFO, stream=None):
    """
    Enables console logging for strilight with a clean, standard formatter.
    """
    if stream is None:
        stream = sys.stderr
    set_log_level(level)
    
    # Avoid adding multiple StreamHandlers
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.NullHandler) for h in logger.handlers):
        handler = logging.StreamHandler(stream)
        formatter = logging.Formatter("[%(levelname)s] [%(name)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)


# Core abstractions
from strilight.engine.vsa import LoopEvaluator, LoopSummary, LoopInvariantContract
from strilight.engine.domains import Interval, StridedInterval, DisjointIntervalSet
from strilight.frontend import SourceLifter, CodeGenerator, accelerate, accelerate_c_source

# Optional low-level architecture abstractions
try:
    from strilight.arch import Instruction, LoopBlock, TraceCompressor
    from strilight.arch.x86 import ConditionExtractor, StaticFlagTracker
except ImportError:
    Instruction = None  # type: ignore
    LoopBlock = None  # type: ignore
    TraceCompressor = None  # type: ignore
    ConditionExtractor = None  # type: ignore
    StaticFlagTracker = None  # type: ignore

def __getattr__(name: str):
    """
    Lazy load optional extension modules on demand (PEP 562).
    """
    try:
        if name in (
            "Tracker",
            "TraceRecord",
            "BackwardSliceTracker",
            "ForwardSliceTracker",
            "Descendant",
            "Ancestor",
        ):
            import strilight.extensions.tracker as t
            return getattr(t, name)
        if name == "BackwardTracker":
            import strilight.extensions.tracker as t
            return getattr(t, "BackwardSliceTracker")
        if name == "Z3Translator":
            from strilight.extensions.translator import Z3Translator
            return Z3Translator
        if name in ("SymbolicStackEngine", "StackByteCell"):
            import strilight.extensions.stack_engine as s
            return getattr(s, name)
        if name == "AnalyzerCore":
            from strilight.extensions.core import AnalyzerCore
            return AnalyzerCore
        if name == "setup_hooks":
            from strilight.extensions.hooks import setup_hooks
            return setup_hooks
        if name == "AngrBridge":
            from strilight.extensions.angr_bridge import AngrBridge
            return AngrBridge
    except ImportError as e:
        raise AttributeError(f"Optional extension module {name!r} is not installed or not included in this distribution: {e}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    # High-Level Facade Functions & Decorators
    "disassemble",
    "compress",
    "evaluate",
    "analyze",
    "accelerate",
    "accelerate_c_source",
    
    # Logging Configuration
    "logger",
    "set_log_level",
    "enable_logging",
    
    # Core Classes
    "Instruction",
    "LoopBlock",
    "TraceCompressor",
    "LoopEvaluator",
    "LoopSummary",
    "LoopInvariantContract",
    "ConditionExtractor",
    "StaticFlagTracker",
    "Interval",
    "StridedInterval",
    "DisjointIntervalSet",
    "SymbolicStackEngine",
    "StackByteCell",
    "SourceLifter",
    "CodeGenerator",
]
