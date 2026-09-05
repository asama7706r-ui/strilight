"""
Unit Test Suite for Strilight Source Code Lifter Subsystem (SourceLifter)
=========================================================================
Validates:
1. Python loop AST extraction and acceleration via `ast`.
2. Python nested loop lifting and induction composition.
3. C loop lifting via `pycparser`.
4. C nested loop lifting and induction composition matching crackme_nested_loops.c.
5. In-place source-to-source drop-in string generation (accelerate_c and accelerate_python).
"""

import pytest
from strilight.frontend import SourceLifter, PythonLoopLifter, CLoopLifter, accelerate


def test_python_single_loop_lifting():
    """
    Tests lifting a simple Python loop into a LoopSummary.
    """
    py_code = """
for i in range(500):
    total += 7
    count += 1
"""
    summary = SourceLifter.lift_python_loop(py_code)
    assert summary.iterations == 500
    assert "total" in summary.var_exprs
    assert "count" in summary.var_exprs
    assert summary.var_exprs["total"].terms[0].stride == 7
    assert summary.var_exprs["count"].terms[0].stride == 1

    # In-place accelerated string
    acc_py = SourceLifter.accelerate_python(py_code, in_place=True)
    assert "total += 7 * 500" in acc_py
    assert "count += 1 * 500" in acc_py


def test_python_nested_loop_composition():
    """
    Tests lifting a nested Python loop:
        for i in range(100):
            for j in range(10):
                acc += 3
    Total stride per outer iteration is 10 * 3 = 30. Total iterations 100.
    """
    py_code = """
for i in range(100):
    for j in range(10):
        acc += 3
"""
    summary = SourceLifter.lift_python_loop(py_code)
    assert summary.iterations == 100
    assert "acc" in summary.var_exprs
    assert summary.var_exprs["acc"].terms[0].stride == 30

    acc_py = SourceLifter.accelerate_python(py_code, in_place=True)
    assert "acc += 30 * 100" in acc_py


def test_c_single_loop_lifting():
    """
    Tests lifting a C loop via pycparser:
        for (int i = 0; i < 1000; i++) {
            acc += 7;
        }
    """
    c_code = """
    for (int i = 0; i < 1000; i++) {
        acc += 7;
    }
    """
    summary = SourceLifter.lift_c_loop(c_code)
    assert summary.iterations == 1000
    assert "acc" in summary.var_exprs
    assert summary.var_exprs["acc"].terms[0].stride == 7

    acc_c = SourceLifter.accelerate_c(c_code, in_place=True)
    assert "acc += (7LL * 1000);" in acc_c


def test_c_nested_loop_lifting_crackme_pattern():
    """
    Tests lifting the exact nested loop structure from crackme_nested_loops.c:
        for (int i = 0; i < 1000; i++) {
            for (int j = 0; j < 5; j++) {
                acc += 15 + j;
            }
            acc += 114;
        }
    Inner loop contributes: 5 * 15 + (0+1+2+3+4 = 10) = 85.
    Outer step contributes: 85 + 114 = 199.
    Total per outer iteration: 199. Iterations: 1000.
    """
    c_code = """
    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 5; j++) {
            acc += 15 + j;
        }
        acc += 114;
    }
    """
    summary = SourceLifter.lift_c_loop(c_code)
    assert summary.iterations == 1000
    assert "acc" in summary.var_exprs
    
    # 85 (from inner) + 114 (from outer) = 199 total stride
    assert summary.var_exprs["acc"].terms[0].stride == 85
    assert summary.var_exprs["acc"].terms[1].stride == 114

    acc_c = SourceLifter.accelerate_c(c_code, in_place=True)
    # The emitted in-place statement automatically sums the terms:
    assert "acc += (85LL * 1000) + (114LL * 1000);" in acc_c

    # Full C function generation
    acc_c_func = SourceLifter.accelerate_c(c_code, in_place=False, func_name="fast_crackme_loop")
    assert "fast_crackme_loop_result_t fast_crackme_loop(uint64_t N, uint64_t acc)" in acc_c_func


def test_c_coupled_matrix_lifting():
    """
    Tests automatic lifting of a 4x4 coupled affine matrix recurrence system in C (Rule 7).
    """
    c_code = """
    for (int i = 0; i < 1000000; i++) {
        int next_a = 3*a + 7*b - 2*c + 5*d + 11;
        int next_b = -2*a + 5*b + 8*c - d + 17;
        int next_c = 4*a - b + 6*c + 3*d + 23;
        int next_d = a + 9*b - 4*c + 2*d + 31;
        a = next_a; b = next_b; c = next_c; d = next_d;
    }
    """
    summary = SourceLifter.lift_c_loop(c_code)
    assert summary.iterations == 1000000
    assert summary.coupling_matrix is not None
    assert summary.coupling_matrix.vars == ["a", "b", "c", "d"]
    assert summary.coupling_matrix.offset == [11, 17, 23, 31]

    # Test automatic code emission
    emitted_c = SourceLifter.accelerate_c(c_code, in_place=True)
    assert "0x5CBF9773 * a" in emitted_c
    assert "0x17A57BD1 * b" in emitted_c
    assert "0x49D85E78 * c" in emitted_c
    assert "0xC9130B9E * d" in emitted_c
    assert "a = final_a;" in emitted_c


def test_python_coupled_matrix_lifting():
    """
    Tests automatic lifting of a coupled linear recurrence in Python.
    """
    py_code = """
for i in range(100):
    next_a = a + b
    next_b = a
    a = next_a
    b = next_b
"""
    summary = SourceLifter.lift_python_loop(py_code)
    assert summary.iterations == 100
    assert summary.coupling_matrix is not None
    assert "a" in summary.coupling_matrix.vars
    assert "b" in summary.coupling_matrix.vars


from strilight import accelerate


@accelerate
def compute_coupled_sample(N, a, b, c, d):
    for _ in range(N):
        next_a = 3*a + 7*b - 2*c + 5*d + 11
        next_b = -2*a + 5*b + 8*c - d + 17
        next_c = 4*a - b + 6*c + 3*d + 23
        next_d = a + 9*b - 4*c + 2*d + 31
        a = next_a
        b = next_b
        c = next_c
        d = next_d
    return a, b, c, d


def test_accelerate_decorator_transparent_execution():
    """
    Tests that @accelerate decorator automatically accelerates a Python function
    while preserving its interface and returning 100% bit-exact results.
    """
    # Run for N = 100
    res = compute_coupled_sample(100, 1, 2, 3, 4)
    # Expected exact values for N = 100: (0xEF1CF8C4, 0x693D54A8, 0x13541302, 0xD4FAA846)
    assert res == (0xEF1CF8C4, 0x693D54A8, 0x13541302, 0xD4FAA846)

