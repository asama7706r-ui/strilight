"""
Backward Compatibility Facade for Strilight VSA Engine.
Re-exports core VSA models, dispatchers, and evaluators from `strilight.engine.vsa`.
"""

from strilight.engine.vsa import (
    ScaleKernel,
    IdentityScale,
    PowerScale,
    LoopTerm,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    TelescopingTerm,
    TelescopingBranch,
    TelescopingCascade,
    RegisterLoopExpr,
    LoopEvaluator,
    LoopSummary,
    LoopInvariantContract,
    AffineExpr,
    RegisterCouplingMatrix,
    VSAInstructionDispatcher,
    SymbolicInductionAnalyzer,
    LoopSMTTranslator,
    LoopStateUpdate,
)

__all__ = [
    "ScaleKernel",
    "IdentityScale",
    "PowerScale",
    "LoopTerm",
    "LinearTerm",
    "PeriodicTerm",
    "GeometricTerm",
    "TelescopingTerm",
    "TelescopingBranch",
    "TelescopingCascade",
    "RegisterLoopExpr",
    "LoopEvaluator",
    "LoopSummary",
    "LoopInvariantContract",
    "AffineExpr",
    "RegisterCouplingMatrix",
    "VSAInstructionDispatcher",
    "SymbolicInductionAnalyzer",
    "LoopSMTTranslator",
    "LoopStateUpdate",
]
