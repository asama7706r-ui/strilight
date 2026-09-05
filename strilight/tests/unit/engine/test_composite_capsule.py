"""
Unit Test Suite for State Tensor Capsules & Block-Diagonal Decomposition (Rule 14.e)
=====================================================================================
Validates:
1. Abstract domain-agnostic CompositeTensorDescriptor (storage_layout=None)
2. StorageLayout memory mapping, struct offsets, and padding
3. VariableCouplingMatrix.decompose_block_diagonal() graph connectivity extraction
4. Equivalence theorem: (A_1 (+) A_2)^N == A_1^N (+) A_2^N
5. decompose_into_capsules() end-to-end integration
"""

import pytest
from strilight.engine.vsa.models import (
    AffineExpr,
    VariableCouplingMatrix,
    StorageLayout,
    CompositeTensorDescriptor,
)


def test_abstract_composite_tensor_descriptor():
    """Validates domain-agnostic capsule with no physical memory layout."""
    capsule = CompositeTensorDescriptor(
        name="particle_state",
        channel_names=["p_x", "p_y", "v_x", "v_y"],
        interface_dof=4
    )
    assert capsule.D == 4
    assert capsule.D_interface == 4
    assert capsule.storage_layout is None
    assert capsule.internal_matrix.dim == 4

    # Setup 2D linear kinematics: p_x += v_x, p_y += v_y
    capsule.internal_matrix.set_affine_row("p_x", AffineExpr({"p_x": 1, "v_x": 1}))
    capsule.internal_matrix.set_affine_row("p_y", AffineExpr({"p_y": 1, "v_y": 1}))

    # Advance 1,000 steps via fast binary exponentiation
    pow_capsule = capsule.pow_mod(1000)
    assert pow_capsule.D == 4
    # Check that p_x coeff of v_x is 1000
    p_x_idx = pow_capsule.internal_matrix.var_to_idx["p_x"]
    v_x_idx = pow_capsule.internal_matrix.var_to_idx["v_x"]
    assert pow_capsule.internal_matrix.matrix[p_x_idx][v_x_idx] == 1000


def test_capsule_with_storage_layout():
    """Validates capsule equipped with memory offsets and alignment for binary/C analysis."""
    layout = StorageLayout(
        field_offsets={"id": 0, "x": 8, "y": 16, "vx": 24, "vy": 32},
        total_stride_bytes=40,
        alignment=8,
        base_register="rbx"
    )
    capsule = CompositeTensorDescriptor(
        name="c_body_struct",
        channel_names=["x", "y", "vx", "vy"],
        interface_dof=2,  # e.g. only positions x, y participate in external contact
        storage_layout=layout
    )
    assert capsule.D == 4
    assert capsule.D_interface == 2
    assert capsule.storage_layout.total_stride_bytes == 40
    assert capsule.storage_layout.alignment == 8
    assert capsule.storage_layout.field_offsets["x"] == 8

    d = capsule.to_dict()
    assert d["interface_dof"] == 2
    assert d["storage_layout"]["total_stride_bytes"] == 40


def test_block_diagonal_fully_connected_matrix():
    """A fully interconnected matrix should remain a single monolithic block."""
    mat = VariableCouplingMatrix(["a", "b", "c"])
    mat.set_affine_row("a", AffineExpr({"a": 1, "b": 2}))
    mat.set_affine_row("b", AffineExpr({"b": 1, "c": 3}))
    mat.set_affine_row("c", AffineExpr({"c": 1, "a": 4}))

    blocks = mat.decompose_block_diagonal()
    assert len(blocks) == 1
    assert blocks[0].vars == ["a", "b", "c"]


def test_block_diagonal_two_independent_clusters():
    """
    Kinematics on X and Y axes are completely independent:
        x_{k+1} = x_k + 3 * vx_k
        vx_{k+1} = vx_k
        y_{k+1} = y_k + 5 * vy_k
        vy_{k+1} = vy_k
    Should decompose cleanly into two 2x2 blocks: {x, vx} (+) {y, vy}.
    """
    mat = VariableCouplingMatrix(["x", "vx", "y", "vy"])
    mat.set_affine_row("x", AffineExpr({"x": 1, "vx": 3}))
    mat.set_affine_row("vx", AffineExpr({"vx": 1}))
    mat.set_affine_row("y", AffineExpr({"y": 1, "vy": 5}))
    mat.set_affine_row("vy", AffineExpr({"vy": 1}))

    blocks = mat.decompose_block_diagonal()
    assert len(blocks) == 2
    
    b1, b2 = blocks
    assert set(b1.vars) == {"x", "vx"}
    assert set(b2.vars) == {"y", "vy"}

    # Verify internal transitions in sub-matrices
    assert b1.dim == 2
    assert b2.dim == 2
    x_idx = b1.var_to_idx["x"]
    vx_idx = b1.var_to_idx["vx"]
    assert b1.matrix[x_idx][vx_idx] == 3

    y_idx = b2.var_to_idx["y"]
    vy_idx = b2.var_to_idx["vy"]
    assert b2.matrix[y_idx][vy_idx] == 5


def test_block_diagonal_power_algebraic_parity():
    """
    Proves the fundamental theorem of Block-Diagonal Direct Sum (Rule 14.c):
        (A_1 (+) A_2)^N == A_1^N (+) A_2^N
    Verifies that raising decoupled sub-matrices yields the exact same state
    as raising the global dense matrix, but in O(1) parallel sub-blocks.
    """
    global_mat = VariableCouplingMatrix(["x1", "x2", "y1", "y2"])
    # Block 1: Fibonacci-like recurrence
    global_mat.set_affine_row("x1", AffineExpr({"x1": 1, "x2": 1}))
    global_mat.set_affine_row("x2", AffineExpr({"x1": 1}))
    # Block 2: Affine counter
    global_mat.set_affine_row("y1", AffineExpr({"y1": 2, "y2": 3}, offset=7))
    global_mat.set_affine_row("y2", AffineExpr({"y2": 1}, offset=1))

    N = 50

    # 1. Compute global matrix power
    global_pow = global_mat.pow_mod(N)

    # 2. Decompose into blocks and compute powers independently
    blocks = global_mat.decompose_block_diagonal()
    assert len(blocks) == 2
    block_pows = [b.pow_mod(N) for b in blocks]

    # 3. Assert bit-exact mathematical parity across all variables and offsets
    for b_pow in block_pows:
        for var in b_pow.vars:
            g_row = global_mat.var_to_idx[var]
            b_row = b_pow.var_to_idx[var]
            
            # Check offset matches
            assert global_pow.offset[g_row] == b_pow.offset[b_row]

            # Check coefficients match
            for src_var in b_pow.vars:
                g_col = global_mat.var_to_idx[src_var]
                b_col = b_pow.var_to_idx[src_var]
                assert global_pow.matrix[g_row][g_col] == b_pow.matrix[b_row][b_col]


def test_decompose_into_capsules():
    """Tests automated decomposition of multi-variable matrix into capsules."""
    mat = VariableCouplingMatrix(["pos_x", "vel_x", "pos_y", "vel_y", "unrelated_flag"])
    mat.set_affine_row("pos_x", AffineExpr({"pos_x": 1, "vel_x": 1}))
    mat.set_affine_row("pos_y", AffineExpr({"pos_y": 1, "vel_y": 2}))
    mat.set_affine_row("unrelated_flag", AffineExpr({"unrelated_flag": 1}, offset=1))

    capsules = mat.decompose_into_capsules(name_prefix="island")
    # Should decompose into 3 independent islands: {pos_x, vel_x}, {pos_y, vel_y}, {unrelated_flag}
    assert len(capsules) == 3
    assert set(capsules[0].channel_names) == {"pos_x", "vel_x"}
    assert set(capsules[1].channel_names) == {"pos_y", "vel_y"}
    assert set(capsules[2].channel_names) == {"unrelated_flag"}
    assert all(isinstance(c, CompositeTensorDescriptor) for c in capsules)
