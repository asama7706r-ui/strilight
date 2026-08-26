import z3
import pytest
from strilight.engine.vsa.models import (
    RegisterLoopExpr,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    TelescopingTerm,
    TelescopingCascade,
    TelescopingBranch,
    LoopSummary,
    IdentityScale,
    PowerScale,
)
from strilight.engine.translator import Z3Translator


def test_compound_ast_linear_and_periodic():
    """
    Test a compound expression combining a LinearTerm and a PeriodicTerm:
        Delta_total(N) = LinearTerm(4) + PeriodicTerm([10, 20])
    For N = 4:
        Linear part: 4 * 4 = 16
        Periodic part: Q = 4 // 2 = 2, R = 0 -> 2 * 30 = 60
        Total delta = 16 + 60 = 76.
    """
    summary = LoopSummary()
    summary.iterations = 10

    reg_expr = RegisterLoopExpr("rax")
    reg_expr.add_term(LinearTerm(stride=4))
    reg_expr.add_term(PeriodicTerm(pattern=[10, 20]))
    summary.register_exprs["rax"] = reg_expr

    translator = Z3Translator()
    translator.solver.add(translator._get_phys_reg("rax") == 100)
    translator.translate_loop_summary(summary, max_iterations=100)

    N = translator.latest_loop_counter
    rax_var = translator.reg_state["rax"]

    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)

    solver.add(N == 4)
    assert solver.check() == z3.sat
    m = solver.model()
    # Initial: 100 + 76 = 176
    assert m[rax_var].as_long() == 176


def test_compound_ast_geometric_and_linear():
    """
    Test a compound expression combining GeometricTerm and LinearTerm:
        Delta_total(N) = LinearTerm(5) + GeometricTerm(base=2, val=1)
    For N = 3:
        Linear part: 5 * 3 = 15
        Geometric part: (2^3 - 1) * 1 = 7 * 1 = 7
        Total delta = 15 + 7 = 22.
    """
    summary = LoopSummary()
    summary.iterations = 10

    reg_expr = RegisterLoopExpr("rbx")
    reg_expr.add_term(LinearTerm(stride=5))
    reg_expr.add_term(GeometricTerm(base=2, val=1))
    summary.register_exprs["rbx"] = reg_expr

    translator = Z3Translator()
    translator.solver.add(translator._get_phys_reg("rbx") == 0)
    translator.translate_loop_summary(summary, max_iterations=100)

    N = translator.latest_loop_counter
    rbx_var = translator.reg_state["rbx"]

    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)

    solver.add(N == 3)
    assert solver.check() == z3.sat
    m = solver.model()
    assert m[rbx_var].as_long() == 22


def test_ast_definition_kill_overwrite():
    """
    Test that set_constant clears all prior terms (Definition-Kill).
    """
    reg_expr = RegisterLoopExpr("rcx")
    reg_expr.add_term(LinearTerm(10))
    reg_expr.add_term(PeriodicTerm([1, 2, 3]))
    assert len(reg_expr.terms) == 2

    reg_expr.set_constant(42)
    assert len(reg_expr.terms) == 0
    assert reg_expr.constant_val == 42


def test_ast_power_scale():
    """
    Test that PowerScale computes base^N * X_0.
    """
    reg_expr = RegisterLoopExpr("rdx", scale_kernel=PowerScale(base=2))
    reg_expr.add_term(LinearTerm(stride=3))
    # State(N) = 2^N * rdx_0 + 3 * N

    summary = LoopSummary()
    summary.register_exprs["rdx"] = reg_expr

    translator = Z3Translator()
    translator.solver.add(translator._get_phys_reg("rdx") == 5)
    translator.translate_loop_summary(summary, max_iterations=100)

    N = translator.latest_loop_counter
    rdx_var = translator.reg_state["rdx"]

    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)

    # For N = 4: 2^4 * 5 + 3 * 4 = 16 * 5 + 12 = 80 + 12 = 92
    solver.add(N == 4)
    assert solver.check() == z3.sat
    m = solver.model()
    assert m[rdx_var].as_long() == 92
