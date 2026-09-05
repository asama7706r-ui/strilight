"""
Unit Test Suite for Static Condensation & Back-Substitution Recovery (Rule 14.b & 14.d)
========================================================================================
Validates:
1. Schur reduction / Interface Condensation (D -> D_interface)
2. Exact algebraic Back-Substitution (recover_internal_state)
3. Zero-loss reconstruction of internal slave variables after N iterations
4. Automated spatial condensation pass in LoopSummary
5. Multi-capsule decoupled parallel code generation in CodeGenerator (Python & C)
"""

import pytest
from strilight.engine.vsa.models import (
    AffineExpr,
    VariableCouplingMatrix,
    StorageLayout,
    CompositeTensorDescriptor,
    LoopSummary,
)
from strilight.frontend.codegen import CodeGenerator


def test_condensation_and_exact_back_substitution():
    """
    Simulates a compound entity (e.g. rigid vehicle body + passenger seat):
      - Master interface variables: x_m (bumper position), v_m (vehicle velocity)
      - Slave internal variables: x_s (seat relative position), temp_s (internal engine sensor)
    
    Equations:
      x_m_{k+1} = x_m_k + v_m_k
      v_m_{k+1} = v_m_k
      x_s_{k+1} = 2 * x_m_k + 5  (slaved to bumper position)
      temp_s_{k+1} = 3 * v_m_k + 10 (slaved to vehicle speed)
    """
    mat = VariableCouplingMatrix(["x_m", "v_m", "x_s", "temp_s"])
    mat.set_affine_row("x_m", AffineExpr({"x_m": 1, "v_m": 1}))
    mat.set_affine_row("v_m", AffineExpr({"v_m": 1}))
    mat.set_affine_row("x_s", AffineExpr({"x_m": 2}, offset=5))
    mat.set_affine_row("temp_s", AffineExpr({"v_m": 3}, offset=10))

    capsule = CompositeTensorDescriptor(
        name="vehicle_system",
        channel_names=["x_m", "v_m", "x_s", "temp_s"],
        internal_matrix=mat,
        interface_dof=2  # only x_m and v_m are exposed
    )
    assert capsule.D == 4
    assert capsule.D_interface == 2

    # Condense internal variables out of the execution loop
    condensed = capsule.condense_to_interface(["x_m", "v_m"])
    assert condensed.D == 2
    assert condensed.channel_names == ["x_m", "v_m"]
    assert "x_s" not in condensed.channel_names
    assert "temp_s" not in condensed.channel_names
    assert len(condensed.recovery_map) == 2

    # Simulate master interface for N = 100 steps
    # Initial state: x_m = 10, v_m = 4
    N = 100
    pow_condensed = condensed.pow_mod(N)
    
    # Calculate final master state via condensed matrix:
    # x_m_final = 1 * 10 + 100 * 4 = 410
    # v_m_final = 1 * 4 = 4
    x_m_idx = pow_condensed.internal_matrix.var_to_idx["x_m"]
    v_m_idx = pow_condensed.internal_matrix.var_to_idx["v_m"]
    final_x_m = pow_condensed.internal_matrix.matrix[x_m_idx][x_m_idx] * 10 + pow_condensed.internal_matrix.matrix[x_m_idx][v_m_idx] * 4
    final_v_m = pow_condensed.internal_matrix.matrix[v_m_idx][v_m_idx] * 4

    assert final_x_m == 410
    assert final_v_m == 4

    # Now recover internal state in O(1) via Back-Substitution:
    recovered = condensed.recover_internal_state({"x_m": final_x_m, "v_m": final_v_m})
    
    # Expected:
    # x_s = 2 * final_x_m + 5 = 2 * 410 + 5 = 825
    # temp_s = 3 * final_v_m + 10 = 3 * 4 + 10 = 22
    assert recovered["x_s"] == 825
    assert recovered["temp_s"] == 22


def test_spatial_condensation_pass_in_loop_summary():
    """Validates automatic detection and decomposition of independent islands in LoopSummary."""
    summary = LoopSummary()
    mat = VariableCouplingMatrix(["x", "vx", "y", "vy"])
    mat.set_affine_row("x", AffineExpr({"x": 1, "vx": 1}))
    mat.set_affine_row("vx", AffineExpr({"vx": 1}))
    mat.set_affine_row("y", AffineExpr({"y": 1, "vy": 2}))
    mat.set_affine_row("vy", AffineExpr({"vy": 1}))

    summary.coupling_matrix = mat
    assert len(summary.capsules) == 0

    # Run spatial condensation pass
    summary.perform_spatial_condensation_pass()
    assert len(summary.capsules) == 2
    assert set(summary.capsules[0].channel_names) == {"x", "vx"}
    assert set(summary.capsules[1].channel_names) == {"y", "vy"}


def test_codegen_multi_capsule_decoupled_emission():
    """Validates that CodeGenerator emits decoupled parallel blocks for multi-capsule summaries."""
    summary = LoopSummary()
    summary.iterations = 1000

    mat = VariableCouplingMatrix(["pos_a", "vel_a", "pos_b", "vel_b"])
    mat.set_affine_row("pos_a", AffineExpr({"pos_a": 1, "vel_a": 3}))
    mat.set_affine_row("vel_a", AffineExpr({"vel_a": 1}))
    mat.set_affine_row("pos_b", AffineExpr({"pos_b": 1, "vel_b": 5}))
    mat.set_affine_row("vel_b", AffineExpr({"vel_b": 1}))

    summary.coupling_matrix = mat
    summary.perform_spatial_condensation_pass()

    # 1. Python code generation
    py_code = CodeGenerator.to_python_statements(summary, N_var="1000", in_place=True)
    assert "Decoupled Block" in py_code
    assert "final_pos_a" in py_code
    assert "final_pos_b" in py_code

    # 2. C code generation
    c_code = CodeGenerator.to_c_statements(summary, N_var="1000", in_place=True)
    assert "Decoupled Block" in c_code
    assert "final_pos_a" in c_code
    assert "final_pos_b" in c_code
