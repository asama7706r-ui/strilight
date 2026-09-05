"""
Unit Test Suite for Spatiotemporal Coordinates & 2D Tick Model (Rule 12)
========================================================================
Validates:
1. SpatiotemporalCoordinate <k, xi> lexicographical ordering and serialization
2. SpatiotemporalTickModel O(1) tick evaluation and branch penalties
3. Continuous space-time state evolution State(k, xi) = A_intra(xi) * (A_inter^k * S_0)
4. Epoch anchoring T_epoch = T_0 + N * T_stride
5. Memory timestamp ordering and RAW hazard resolution in SymbolicStackEngine
6. SMT-LIB2 / Z3 closed-form AST generation and solver verification
"""

import z3
import pytest
from strilight.engine.vsa.models import (
    SpatiotemporalCoordinate,
    SpatiotemporalTickModel,
    CompositeTensorDescriptor,
    VariableCouplingMatrix,
    AffineExpr,
    LoopSummary,
)
from strilight.engine.vsa.smt_translator import LoopSMTTranslator
from strilight.extensions.stack_engine import SymbolicStackEngine, StackByteCell


def test_spatiotemporal_coordinate_ordering():
    """Validates 2D lexicographical ordering: <k, xi>."""
    c1 = SpatiotemporalCoordinate(k=1, xi=2)
    c2 = SpatiotemporalCoordinate(k=1, xi=5)
    c3 = SpatiotemporalCoordinate(k=2, xi=0)
    c4 = SpatiotemporalCoordinate(k=2, xi=0)

    assert c1 < c2
    assert c2 < c3
    assert c1 < c3
    assert c3 == c4
    assert not (c3 < c4)
    assert not (c4 < c3)

    # Dictionary round-trip
    d = c1.to_dict()
    assert d == {"k": 1, "xi": 2}
    c_recovered = SpatiotemporalCoordinate.from_dict(d)
    assert c_recovered == c1


def test_tick_model_eval_and_branch_penalties():
    """Validates scalar tick calculation, branch penalties, and epoch anchoring."""
    model = SpatiotemporalTickModel(
        T_0=100,
        inter_stride=10,
        intra_steps=4,
        branch_penalties={"slow_branch": 5, "debug_log": 2}
    )

    # 1. Base iteration 0, phase 0
    assert model.eval_tick(k=0, xi=0) == 100

    # 2. Iteration 5, phase 3
    assert model.eval_tick(k=5, xi=3) == 100 + (5 * 10) + 3  # 153

    # 3. Iteration 5, phase 3 with branch taken
    tick_with_branch = model.eval_tick(k=5, xi=3, branch_mask={"slow_branch": True})
    assert tick_with_branch == 153 + 5  # 158

    # 4. Epoch exit tick for N = 50 iterations
    assert model.eval_epoch(N=50) == 100 + (50 * 10)  # 600

    # 5. Symbolic formulations
    sym_tick = model.eval_tick(k="k_iter", xi=2)
    assert "k_iter * 10" in sym_tick
    sym_epoch = model.eval_epoch(N="N_loop")
    assert "N_loop * 10" in sym_epoch


def test_continuous_spacetime_state_evolution():
    """
    Rule 12.b: State(k, xi) = A_intra(xi) * (A_inter^k * S_0) + C(k, xi).
    Tests advancement across k full cycles plus micro-step xi.
    """
    # Inter-iteration dynamics: x += 10, y += 20 per cycle
    inter_mat = VariableCouplingMatrix(["x", "y"])
    inter_mat.set_affine_row("x", AffineExpr({"x": 1}, offset=10))
    inter_mat.set_affine_row("y", AffineExpr({"y": 1}, offset=20))
    capsule = CompositeTensorDescriptor(
        name="pos_capsule",
        channel_names=["x", "y"],
        internal_matrix=inter_mat
    )

    # Intra-iteration micro-step: x += 1, y += 2 per micro-step
    intra_mat = VariableCouplingMatrix(["x", "y"])
    intra_mat.set_affine_row("x", AffineExpr({"x": 1}, offset=1))
    intra_mat.set_affine_row("y", AffineExpr({"y": 1}, offset=2))

    model = SpatiotemporalTickModel(T_0=0, inter_stride=4, intra_steps=4)

    # Initial state: x = 0, y = 0
    # Evaluate at cycle k = 5, micro-step xi = 2:
    # After 5 cycles: x = 50, y = 100
    # After 2 micro-steps: x = 50 + 2 = 52, y = 100 + 4 = 104
    st = model.eval_state_at(
        k=5,
        xi=2,
        initial_state={"x": 0, "y": 0},
        capsule=capsule,
        intra_matrix=intra_mat
    )
    assert st["x"] == 52
    assert st["y"] == 104


def test_memory_raw_hazard_resolution_in_stack_engine():
    """
    Rule 12.c: Tests spatiotemporal memory timestamping and RAW hazard resolution.
    Overwrites the same memory address across iterations, ensuring reads at specific
    timestamps only see the latest write strictly prior to or at that timestamp.
    """
    engine = SymbolicStackEngine()
    addr = 0x4000

    # Write 1: at coordinate <k=1, xi=0>, writes 0x11111111
    t1 = SpatiotemporalCoordinate(k=1, xi=0)
    engine.write_val(addr, 0x11111111, size_bytes=4, origin_instr="write_k1", timestamp=t1)

    # Write 2: at coordinate <k=3, xi=2>, writes 0x33333333
    t2 = SpatiotemporalCoordinate(k=3, xi=2)
    engine.write_val(addr, 0x33333333, size_bytes=4, origin_instr="write_k3", timestamp=t2)

    # Query 1: read at coordinate <k=2, xi=0>
    # Must see Write 1 (0x11111111), NOT Write 2
    read_t2 = SpatiotemporalCoordinate(k=2, xi=0)
    val_at_t2 = engine.read_val(addr, size_bytes=4, tick=read_t2)
    simp_val = z3.simplify(val_at_t2)
    assert hex(simp_val.as_long()) == hex(0x11111111)

    # Query 2: read at coordinate <k=5, xi=0>
    # Must see Write 2 (0x33333333)
    read_t5 = SpatiotemporalCoordinate(k=5, xi=0)
    val_at_t5 = engine.read_val(addr, size_bytes=4, tick=read_t5)
    simp_val = z3.simplify(val_at_t5)
    assert hex(simp_val.as_long()) == hex(0x33333333)


def test_smt_translator_tick_and_epoch_anchor():
    """
    Rule 12.d: Tests Z3 AST generation for 2D ticks and epoch anchoring with solver verification.
    """
    model = SpatiotemporalTickModel(
        T_0=50,
        inter_stride=8,
        intra_steps=3,
        branch_penalties={"unlikely_handler": 12}
    )

    N = z3.BitVec("N", 64)
    xi = z3.BitVec("xi", 64)
    cond_branch = z3.Bool("cond_branch")

    # Build tick AST
    tick_ast = LoopSMTTranslator.build_spatiotemporal_tick_ast(
        model,
        N_ast=N,
        xi_ast=xi,
        branch_conds={"unlikely_handler": cond_branch},
        bit_size=64
    )

    # Build epoch anchor AST
    T_epoch_sym, anchor_constraint = LoopSMTTranslator.build_epoch_anchor_ast(
        model,
        N_ast=N,
        bit_size=64
    )

    # Verify with Z3 solver:
    # If N == 10, xi == 2, cond_branch == True:
    # Tick == 50 + (10 * 8) + 2 + 12 = 144
    # T_epoch == 50 + (10 * 8) = 130
    s = z3.Solver()
    s.add(N == 10)
    s.add(xi == 2)
    s.add(cond_branch == True)
    s.add(anchor_constraint)

    assert s.check() == z3.sat
    m = s.model()

    eval_tick = m.eval(tick_ast).as_long()
    assert eval_tick == 144

    eval_epoch = m.eval(T_epoch_sym).as_long()
    assert eval_epoch == 130


def test_loop_summary_spatiotemporal_integration():
    """Tests LoopSummary integration with tick_model."""
    summary = LoopSummary()
    summary.iterations = 100
    summary.tick_model = SpatiotemporalTickModel(T_0=10, inter_stride=5)

    assert summary.get_tick(k=10, xi=1) == 10 + (10 * 5) + 1  # 61
    assert summary.get_epoch_tick() == 10 + (100 * 5)  # 510
