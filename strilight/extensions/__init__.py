"""
Strilight Optional & Experimental Extensions Layer.
Houses dynamic tracers, emulators, stack simulators, hooks, and external analysis tools.
"""


def __getattr__(name: str):
    """
    Lazy load extensions modules (PEP 562) to decouple dependencies.
    """
    if name == "STOP_FUNCTIONS":
        from strilight.extensions.stop_dict import STOP_FUNCTIONS
        return STOP_FUNCTIONS
    if name in ("PathTree", "PathNode"):
        import strilight.extensions.path_tree as p
        return getattr(p, name)
    if name == "setup_hooks":
        from strilight.extensions.hooks import setup_hooks
        return setup_hooks
    if name == "AnalyzerCore":
        from strilight.extensions.core import AnalyzerCore
        return AnalyzerCore
    if name in ("SymbolicStackEngine", "StackByteCell"):
        import strilight.extensions.stack_engine as s
        return getattr(s, name)
    if name == "Z3Translator":
        from strilight.extensions.translator import Z3Translator
        return Z3Translator
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
    if name == "AngrBridge":
        from strilight.extensions.angr_bridge import AngrBridge
        return AngrBridge
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "STOP_FUNCTIONS",
    "PathTree",
    "PathNode",
    "setup_hooks",
    "AnalyzerCore",
    "SymbolicStackEngine",
    "StackByteCell",
    "Z3Translator",
    "Tracker",
    "TraceRecord",
    "BackwardSliceTracker",
    "ForwardSliceTracker",
    "Descendant",
    "Ancestor",
    "AngrBridge",
]
