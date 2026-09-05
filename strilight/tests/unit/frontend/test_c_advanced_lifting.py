"""
Strilight C Advanced Loop Lifting Tests
========================================
Validates enhanced CLoopLifter capabilities matching Python:
- Unary operators: x++, ++y, z--, --w
- Scalar self-assignments: x = x + c, x = x - c, x = c + x
- Geometric & bitwise progressions: x *= 2, x <<= 1, x *= 3
- Periodic & modulo branch patterns: if (i % P == 0), if (i % P == r), if (!(i % P))
- Coupled recurrences mixing unary operators and assignments
- End-to-end #pragma strilight accelerate source transformation
"""

import pytest
from strilight.frontend.c.lifter import CLoopLifter
from strilight.frontend.source_lifter import SourceLifter
from strilight.engine.vsa.models import PowerScale, PeriodicTerm, LinearTerm


def test_c_unary_increments_and_decrements():
    c_loop = """
    for (int i = 0; i < 100; i++) {
        x++;
        ++y;
        z--;
        --w;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.iterations == 100
    assert "x" in summary.var_exprs
    assert "y" in summary.var_exprs
    assert "z" in summary.var_exprs
    assert "w" in summary.var_exprs

    assert summary.var_exprs["x"].terms[0].stride == 1
    assert summary.var_exprs["y"].terms[0].stride == 1
    assert summary.var_exprs["z"].terms[0].stride == -1
    assert summary.var_exprs["w"].terms[0].stride == -1

    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "x += (1LL * 100);" in fast_c or "x += 100" in fast_c
    assert "y += (1LL * 100);" in fast_c or "y += 100" in fast_c
    assert "z += (-1LL * 100);" in fast_c or "z += -100" in fast_c


def test_c_scalar_self_assignment():
    c_loop = """
    for (int i = 0; i < 50; i++) {
        x = x + 5;
        y = y - 3;
        a = 10 + a;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.iterations == 50
    assert summary.var_exprs["x"].terms[0].stride == 5
    assert summary.var_exprs["y"].terms[0].stride == -3
    assert summary.var_exprs["a"].terms[0].stride == 10


def test_c_geometric_and_bitwise_shift():
    c_loop = """
    for (int i = 0; i < 16; i++) {
        w *= 2;
        v <<= 1;
        u *= 3;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.iterations == 16
    assert isinstance(summary.var_exprs["w"].scale_kernel, PowerScale)
    assert summary.var_exprs["w"].scale_kernel.base == 2

    assert isinstance(summary.var_exprs["v"].scale_kernel, PowerScale)
    assert summary.var_exprs["v"].scale_kernel.base == 2

    assert isinstance(summary.var_exprs["u"].scale_kernel, PowerScale)
    assert summary.var_exprs["u"].scale_kernel.base == 3

    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "(1ULL << 16) * w" in fast_c
    assert "(1ULL << 16) * v" in fast_c
    assert "pow(3, 16) * u" in fast_c


def test_c_periodic_modulo_branch():
    c_loop = """
    for (int i = 0; i < 90; i++) {
        if (i % 3 == 0) {
            b += 7;
        }
        if (i % 2 == 1) {
            c++;
        } else {
            c += 3;
        }
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.iterations == 90
    assert "b" in summary.var_exprs
    assert "c" in summary.var_exprs

    b_term = summary.var_exprs["b"].terms[0]
    assert isinstance(b_term, PeriodicTerm)
    assert b_term.pattern == [7, 0, 0]

    c_term = summary.var_exprs["c"].terms[0]
    assert isinstance(c_term, PeriodicTerm)
    # i % 2 == 1 matches remainder 1 -> d_true=1, remainder 0 -> d_false=3
    assert c_term.pattern == [3, 1]

    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    # For b: (90 / 3) * 7 = 30 * 7 = 210
    assert "b += ((90 / 3) * 7);" in fast_c
    # For c: (90 / 2) * 4 = 45 * 4 = 180
    assert "c += ((90 / 2) * 4);" in fast_c


def test_c_coupled_with_unary_operators():
    c_loop = """
    for (int i = 0; i < 10; i++) {
        x++;
        y += x;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.coupling_matrix is not None
    assert not summary.coupling_matrix.is_identity()
    assert "x" in summary.coupling_matrix.vars
    assert "y" in summary.coupling_matrix.vars


def test_accelerate_c_source_advanced_integration():
    c_source = """
    #include <stdio.h>
    
    void process_data() {
        int count = 0;
        int scale = 1;
        int bonus = 0;
        
        #pragma strilight accelerate
        for (int i = 0; i < 100; i++) {
            count++;
            scale <<= 1;
            if (i % 5 == 0) {
                bonus += 10;
            }
        }
        
        printf("%d %d %d\\n", count, scale, bonus);
    }
    """
    accelerated = SourceLifter.accelerate_c_source(c_source)

    assert "/* [strilight] Accelerated O(1)/O(log N) kernel */" in accelerated
    assert "for (int i = 0; i < 100; i++)" not in accelerated
    assert "bonus += ((100 / 5) * 10);" in accelerated
    assert "scale = (1ULL << 100) * scale;" in accelerated
    assert "count += (1LL * 100);" in accelerated
