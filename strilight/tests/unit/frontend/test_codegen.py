"""
Unit Test Suite for Strilight Code Generation Subsystem (CodeGenerator)
========================================================================
Validates:
1. Python expression, statements, and complete function code generation with variable name preservation.
2. Direct compilation to executable in-memory callable function.
3. Ground-truth execution accuracy of O(1) callable against native iterative loops.
4. C/C++ in-place statements and typed function code generation.
5. High-performance execution across linear, periodic, geometric, and telescoping terms.
"""

import time
import pytest
from strilight.engine.vsa import (
    VariableLoopExpr,
    LoopSummary,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    TelescopingTerm,
    TelescopingCascade,
    TelescopingBranch,
    PowerScale,
)
from strilight.frontend import CodeGenerator


def test_linear_loop_python_and_c_codegen():
    """
    Tests code generation for a linear loop:
        total += 7 * N
        count += 1 * N
    """
    summary = LoopSummary()
    summary.iterations = 1000
    
    expr_total = VariableLoopExpr("total").add_term(LinearTerm(stride=7))
    expr_count = VariableLoopExpr("count").add_term(LinearTerm(stride=1))
    summary.var_exprs["total"] = expr_total
    summary.var_exprs["count"] = expr_count

    # 1. In-place Python Statements (Drop-in Loop Replacement)
    py_stmts = summary.to_python_statements()
    assert "count += 1 * N" in py_stmts
    assert "total += 7 * N" in py_stmts

    # 2. In-place C Statements (Drop-in Loop Replacement)
    c_stmts = summary.to_c_statements()
    assert "count += (1LL * N);" in c_stmts
    assert "total += (7LL * N);" in c_stmts

    # 3. Python Function Code Emission with preserved names
    py_code = summary.to_python_code(func_name="fast_linear_step", preserve_names=True)
    assert "def fast_linear_step(N, count, total):" in py_code
    assert "total = total + 7 * N" in py_code

    # 4. Python Callable Compilation & Execution
    fn = summary.to_python_callable(func_name="fast_linear_step", preserve_names=True)
    res = fn(N=1000, count=0, total=100)
    assert res["total"] == 100 + (7 * 1000)
    assert res["count"] == 0 + (1 * 1000)

    # 5. C Function Code Emission
    c_code = summary.to_c_code(func_name="fast_linear_step", preserve_names=True)
    assert "fast_linear_step_result_t fast_linear_step(uint64_t N, uint64_t count, uint64_t total)" in c_code
    assert "res.total = total + (7LL * N);" in c_code


def test_geometric_and_power_scale_codegen():
    """
    Tests code generation with PowerScale (base^N * X_0) and GeometricTerm.
    """
    summary = LoopSummary()
    
    expr_acc = VariableLoopExpr("acc", scale_kernel=PowerScale(base=2))
    expr_acc.add_term(GeometricTerm(base=2, val=5))
    summary.var_exprs["acc"] = expr_acc

    # Python Callable
    fn = summary.to_python_callable(func_name="fast_power_step", preserve_names=True)
    # For N = 4, acc = 3:
    # Scale: 2^4 * 3 = 16 * 3 = 48
    # Geometric: (2^4 - 1) * 5 = 15 * 5 = 75
    # Total: 48 + 75 = 123
    res = fn(N=4, acc=3)
    assert res["acc"] == 123

    # C Code
    c_code = summary.to_c_code(func_name="fast_power_step", preserve_names=True)
    assert "(1ULL << N) * acc" in c_code


def test_telescoping_cascade_codegen_and_execution():
    """
    Tests code generation for an M-branch Telescoping Cascade (Theorem 5).
    Replicates the logic of crackme_telescoping (P = 4, deltas = 10, 25, 30, 40 -> cycle_sum = 105).
    """
    summary = LoopSummary()
    summary.iterations = 1000

    cascade = TelescopingCascade(target_var="acc")
    cascade.add_branch(TelescopingBranch(name="b0", deltas={"acc": 10}))
    cascade.add_branch(TelescopingBranch(name="b1", deltas={"acc": 25}))
    cascade.add_branch(TelescopingBranch(name="b2", deltas={"acc": 30}))
    cascade.add_branch(TelescopingBranch(name="b3", deltas={"acc": 40}))

    expr_acc = VariableLoopExpr("acc").add_term(TelescopingTerm(cascade=cascade, target_var="acc"))
    summary.var_exprs["acc"] = expr_acc

    # 1. In-place Drop-in Statements
    py_stmts = summary.to_python_statements()
    assert py_stmts == "acc += (N // 4) * 105"

    c_stmts = summary.to_c_statements()
    assert c_stmts == "acc += ((N / 4) * 105);"

    # 2. Python Code Emission
    py_code = summary.to_python_code(func_name="fast_telescoping", preserve_names=True)
    assert "def fast_telescoping(N, acc):" in py_code
    assert "acc + N // 4 * 105" in py_code

    # 3. Python Callable Execution
    fn = summary.to_python_callable(func_name="fast_telescoping", preserve_names=True)
    # Initial: 0x1000 (4096), N = 1000 (250 cycles * 105 = 26250) -> 30346
    res = fn(N=1000, acc=0x1000)
    assert res["acc"] == 30346

    # 4. Ground Truth Verification against native iterative while-loop
    native_acc = 0x1000
    for i in range(1000):
        mode = i % 4
        if mode == 0: native_acc += 10
        elif mode == 1: native_acc += 25
        elif mode == 2: native_acc += 30
        else: native_acc += 40
    assert res["acc"] == native_acc


def test_o1_callable_speedup_microbenchmark():
    """
    Validates that the synthesized O(1) Python callable executes in microsecond scale
    even when N is massive (e.g. 100,000,000).
    """
    summary = LoopSummary()
    summary.var_exprs["x"] = VariableLoopExpr("x").add_term(LinearTerm(stride=13))
    
    fn = summary.to_python_callable(func_name="fast_bench", preserve_names=True)

    # Run for N = 100 Million
    N_huge = 100_000_000
    t0 = time.perf_counter()
    res = fn(N=N_huge, x=42)
    t1 = time.perf_counter()

    elapsed_ms = (t1 - t0) * 1000.0
    assert res["x"] == 42 + (13 * N_huge)
    assert elapsed_ms < 1.0, f"O(1) callable was unexpectedly slow: {elapsed_ms}ms"
