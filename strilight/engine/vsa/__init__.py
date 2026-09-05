"""
Strilight Value Set Analysis (VSA) Engine (strilight.engine.vsa)
================================================================
Mathematical models, single-pass symbolic induction, loop evaluation,
and SMT closed-form translation.
"""

from strilight.engine.vsa.models import (
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
    VariableLoopExpr,
    RegisterLoopExpr,
    AffineExpr,
    VariableCouplingMatrix,
    RegisterCouplingMatrix,
    ArrayDescriptor,
    ArraySliceMutation,
    StorageLayout,
    CompositeTensorDescriptor,
    SpatiotemporalCoordinate,
    SpatiotemporalTickModel,
    OrbitCarrierDescriptor,
    PerturbationEpochModel,
    OrbitPerturbationSystem,
    LoopInvariantContract,
    LoopSummary,
)
from strilight.engine.vsa.symbolic import SymbolicInductionAnalyzer
from strilight.engine.vsa.evaluator import LoopEvaluator
from strilight.engine.vsa.smt_translator import LoopSMTTranslator, LoopStateUpdate

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
    "VariableLoopExpr",
    "RegisterLoopExpr",
    "AffineExpr",
    "VariableCouplingMatrix",
    "RegisterCouplingMatrix",
    "ArrayDescriptor",
    "ArraySliceMutation",
    "StorageLayout",
    "CompositeTensorDescriptor",
    "SpatiotemporalCoordinate",
    "SpatiotemporalTickModel",
    "OrbitCarrierDescriptor",
    "PerturbationEpochModel",
    "OrbitPerturbationSystem",
    "LoopInvariantContract",
    "LoopSummary",
    "SymbolicInductionAnalyzer",
    "LoopEvaluator",
    "LoopSMTTranslator",
    "LoopStateUpdate",
]
