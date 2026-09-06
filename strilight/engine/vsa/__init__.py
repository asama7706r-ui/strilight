"""
Strilight Value Set Analysis (VSA) Engine (strilight.engine.vsa)
================================================================
Pure mathematical models, universal loop recurrence ASTs, and SMT closed-form translation.
This package is strictly mathematical and architecture-agnostic.
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
    "LoopSMTTranslator",
    "LoopStateUpdate",
]
