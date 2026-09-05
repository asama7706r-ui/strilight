"""
Strilight Engine Subpackage
===========================
Provides core abstract interpretation, domains, and mathematical loop models.
"""

from strilight.engine.abstract_state import AbstractState


def __getattr__(name: str):
    """
    Lazy load engine subsystems, architecture and extension modules with PEP 562 for backward compatibility.
    """
    if name in (
        "LoopEvaluator",
        "LoopSummary",
        "LoopInvariantContract",
        "StorageLayout",
        "CompositeTensorDescriptor",
        "SpatiotemporalCoordinate",
        "SpatiotemporalTickModel",
        "OrbitCarrierDescriptor",
        "PerturbationEpochModel",
        "OrbitPerturbationSystem"
    ):
        import strilight.engine.vsa as vsa
        return getattr(vsa, name)
    if name in ("Instruction", "LoopBlock", "TraceCompressor"):
        import strilight.arch as a
        return getattr(a, name)
    if name in (
        "ConditionExtractor",
        "StaticFlagTracker",
        "REGISTER_SIZES",
        "REGISTER_HIERARCHY",
        "REGISTER_MASKS",
        "PHYSICAL_REGS",
        "REG_TO_BASE",
        "BASE_TO_REGS",
    ):
        import strilight.arch.x86 as x86
        return getattr(x86, name)
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
    if name in ("PathTree", "PathNode"):
        import strilight.extensions.path_tree as p
        return getattr(p, name)
    if name == "AnalyzerCore":
        from strilight.extensions.core import AnalyzerCore
        return AnalyzerCore
    if name == "setup_hooks":
        from strilight.extensions.hooks import setup_hooks
        return setup_hooks
    if name == "STOP_FUNCTIONS":
        from strilight.extensions.stop_dict import STOP_FUNCTIONS
        return STOP_FUNCTIONS
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
