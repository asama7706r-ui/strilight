"""
Backward Compatibility Facade for Strilight VSA Engine.
Re-exports core VSA models, dispatchers, and evaluators from `strilight.engine.vsa`.
"""

from strilight.engine.vsa import (
    LoopEvaluator,
    LoopSummary,
    LoopInvariantContract,
    AffineExpr,
    RegisterCouplingMatrix,
    VSAInstructionDispatcher,
    SymbolicInductionAnalyzer,
)

__all__ = [
    "LoopEvaluator",
    "LoopSummary",
    "LoopInvariantContract",
    "AffineExpr",
    "RegisterCouplingMatrix",
    "VSAInstructionDispatcher",
    "SymbolicInductionAnalyzer",
]
