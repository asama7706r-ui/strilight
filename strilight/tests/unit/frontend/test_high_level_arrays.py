import pytest
import logging
from strilight.frontend.source_lifter import SourceLifter, PythonLoopLifter, accelerate
from strilight.engine.vsa.models import PeriodicTerm


def test_lift_array_modulo_subscript():
    """Verify scope array extraction and PeriodicTerm synthesis from modulo indexing."""
    code = """
table = [10, 25, 40, 15]
acc = 0
for i in range(N):
    acc += table[i % 4]
"""
    summary = SourceLifter.lift_python_loop(code)

    assert "table" in summary.array_descriptors
    desc = summary.array_descriptors["table"]
    assert desc.length == 4
    assert desc.elements == [10, 25, 40, 15]
    assert desc.cycle_sum == 90

    assert "acc" in summary.var_exprs
    expr = summary.var_exprs["acc"]
    assert len(expr.terms) == 1
    term = expr.terms[0]
    assert isinstance(term, PeriodicTerm)
    assert term.pattern == [10, 25, 40, 15]


def test_accelerate_python_array_execution():
    """Verify generated in-place Python statement produces 100% bit-exact results for any N."""
    code = """
table = [10, 25, 40, 15]
acc = 0
for i in range(N):
    acc += table[i % 4]
"""
    stmts = SourceLifter.accelerate_python(code)
    # stmts should look like: acc += ((N // 4) * 90 + (0, 10, 35, 75)[(N) % 4])

    table = [10, 25, 40, 15]

    for N_test in [0, 1, 2, 3, 4, 7, 10, 15, 99, 100, 1003, 1_000_000]:
        # Concrete ground truth
        expected = sum(table[i % 4] for i in range(N_test))

        # Accelerated closed-form evaluation
        local_scope = {"acc": 0, "N": N_test}
        exec(stmts, {}, local_scope)
        assert local_scope["acc"] == expected, f"Mismatch at N={N_test}: got {local_scope['acc']}, expected {expected}"


GLOBAL_SBOX = [7, 14, 21, 28]

@accelerate
def accelerated_sbox_sum(N: int) -> int:
    acc = 0
    for i in range(N):
        acc += GLOBAL_SBOX[i % 4]
    return acc


def test_accelerate_decorator_with_global_array():
    """Verify @accelerate decorator extracts globals and accelerates in O(1)."""
    for N_test in [0, 1, 3, 4, 10, 100, 1_000_000]:
        expected = sum(GLOBAL_SBOX[i % 4] for i in range(N_test))
        res = accelerated_sbox_sum(N_test)
        assert res == expected, f"Mismatch for N={N_test}"


def test_bitwise_mask_array_indexing():
    """Verify bitwise AND indexing table[(i * 2) & 3] is correctly lifted."""
    code = """
table = [5, 12, 19, 26]
acc = 0
for i in range(N):
    acc += table[(i * 2) & 3]
"""
    summary = SourceLifter.lift_python_loop(code)
    assert "acc" in summary.var_exprs
    term = summary.var_exprs["acc"].terms[0]
    assert isinstance(term, PeriodicTerm)
    # k=0: (0*2)&3=0 -> table[0]=5
    # k=1: (1*2)&3=2 -> table[2]=19
    # k=2: (2*2)&3=0 -> table[0]=5
    # k=3: (3*2)&3=2 -> table[2]=19
    assert term.pattern == [5, 19, 5, 19]

    stmts = SourceLifter.accelerate_python(code)
    table = [5, 12, 19, 26]
    for N_test in [0, 1, 2, 5, 100, 500_000]:
        expected = sum(table[(i * 2) & 3] for i in range(N_test))
        local_scope = {"acc": 0, "N": N_test}
        exec(stmts, {}, local_scope)
        assert local_scope["acc"] == expected


def test_array_subtraction_and_scale():
    """Verify scaled subtraction from array: acc -= table[i % 4] * 2."""
    code = """
table = [10, 20, 30, 40]
acc = 1000
for i in range(N):
    acc -= table[i % 4] * 2
"""
    summary = SourceLifter.lift_python_loop(code)
    assert "acc" in summary.var_exprs
    term = summary.var_exprs["acc"].terms[0]
    assert isinstance(term, PeriodicTerm)
    assert term.pattern == [-20, -40, -60, -80]

    stmts = SourceLifter.accelerate_python(code)
    table = [10, 20, 30, 40]
    for N_test in [0, 1, 4, 10, 50]:
        expected = 1000 - sum(table[i % 4] * 2 for i in range(N_test))
        local_scope = {"acc": 1000, "N": N_test}
        exec(stmts, {}, local_scope)
        assert local_scope["acc"] == expected


def test_out_of_bounds_warning(caplog):
    """Verify out-of-bounds indexing table[i + 50] logs warning."""
    code = """
table = [1, 2, 3]
acc = 0
for i in range(10):
    acc += table[i + 50]
"""
    with caplog.at_level(logging.WARNING):
        summary = SourceLifter.lift_python_loop(code)

    assert any("OUT OF BOUNDS" in rec.message for rec in caplog.records)
