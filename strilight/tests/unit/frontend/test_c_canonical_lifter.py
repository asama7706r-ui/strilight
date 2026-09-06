"""
Strilight C Canonical Symbolic Transition Lifter Tests
======================================================
Validates:
- Universal LValue Normalization for Struct Arrays: bodies[i].x += delta
- Universal Loop Bounds Formula:
  - Non-unit step strides: for (int i = 0; i < 100; i += 2) -> N = 50
  - Non-zero start values: for (int i = 10; i < 60; i++) -> N = 50
  - Countdown loops: for (int i = 50; i > 0; i--) -> N = 50
- While loop acceleration: while (i < 100) { x += 3; i++; }
"""

import pytest
from strilight.frontend.c.lifter import CLoopLifter
from strilight.frontend.source_lifter import SourceLifter


def test_struct_array_mutation():
    c_loop = """
    for (int i = 0; i < 100; i++) {
        bodies[i].x += 5;
        bodies[i].y -= 2;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    assert summary.iterations == 100
    assert "bodies.x" in summary.array_mutations
    assert "bodies.y" in summary.array_mutations

    assert summary.array_mutations["bodies.x"].delta == 5
    assert summary.array_mutations["bodies.y"].delta == -2

    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "bodies[_i].x += 5" in fast_c
    assert "bodies[_i].y -= 2" in fast_c


def test_universal_bounds_step_stride():
    c_loop = """
    for (int i = 0; i < 100; i += 2) {
        total += 1;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    # 100 / 2 = 50 iterations
    assert summary.iterations == 50
    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "total += (1LL * 50);" in fast_c


def test_universal_bounds_non_zero_start():
    c_loop = """
    for (int i = 10; i < 60; i++) {
        total += 2;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    # 60 - 10 = 50 iterations
    assert summary.iterations == 50
    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "total += (2LL * 50);" in fast_c


def test_universal_bounds_countdown_loop():
    c_loop = """
    for (int i = 50; i > 0; i--) {
        acc += 4;
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_loop)

    # 50 down to 1 = 50 iterations
    assert summary.iterations == 50
    fast_c = SourceLifter.accelerate_c(c_loop, in_place=True)
    assert "acc += (4LL * 50);" in fast_c


def test_while_loop_acceleration():
    c_source = """
    void compute() {
        int i = 0;
        int total = 0;
        #pragma strilight accelerate
        while (i < 100) {
            total += 3;
            i++;
        }
    }
    """
    accelerated = SourceLifter.accelerate_c_source(c_source)

    assert "/* [strilight] Accelerated O(1)/O(log N) kernel */" in accelerated
    assert "while (i < 100)" not in accelerated
    assert "total += (3LL * 100);" in accelerated


def test_while_loop_countdown():
    c_source = """
    void countdown() {
        int n = 40;
        int energy = 1000;
        #pragma strilight accelerate
        while (n > 0) {
            energy -= 15;
            n--;
        }
    }
    """
    accelerated = SourceLifter.accelerate_c_source(c_source)

    assert "/* [strilight] Accelerated O(1)/O(log N) kernel */" in accelerated
    assert "while (n > 0)" not in accelerated
    assert "energy += (-15LL * n);" in accelerated or "energy += (-15LL * 40);" in accelerated or "energy -= (15LL * n);" in accelerated
