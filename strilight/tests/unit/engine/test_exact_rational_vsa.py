"""
Unit Test Suite for Exact Rational Arithmetic over Q (Rule 14 & Rule 7)
=======================================================================
Validates:
1. Exact rational linear combinations in AffineExpr (zero roundoff drift)
2. Rational matrix exponentiation in VariableCouplingMatrix
3. Exact static condensation & back-substitution with fractional coupling
4. C loop lifter exact fractional constant and division lifting
5. Python loop lifter exact fractional constant lifting via scope resolution
"""

from fractions import Fraction
import pytest

from strilight.engine.vsa.models import (
    AffineExpr,
    VariableCouplingMatrix,
    CompositeTensorDescriptor,
)
from strilight.frontend.resolver import CrossFileResolver
from strilight.frontend.c.lifter import CLoopLifter
from strilight.frontend.python.lifter import PythonLoopLifter


def test_affine_expr_exact_rational():
    """Test exact rational operations in AffineExpr: 1/3 * 3 == 1."""
    f1 = Fraction(1, 3)
    e1 = AffineExpr({"x": f1}, offset=Fraction(2, 5))

    # Multiply by 3: coeff should become exact integer 1
    e2 = e1.mul_const(3)
    assert e2.coeffs["x"] == 1
    assert isinstance(e2.coeffs["x"], int)
    assert e2.offset == Fraction(6, 5)

    # Add 4/5 to offset: 6/5 + 4/5 = 10/5 = 2 (exact int)
    e3 = e2 + Fraction(4, 5)
    assert e3.offset == 2
    assert isinstance(e3.offset, int)

    # Subtract pure register
    e4 = e3 - AffineExpr.from_reg("x")
    assert "x" not in e4.coeffs
    assert e4.is_constant()
    assert e4.offset == 2


def test_matrix_exact_rational_exponentiation():
    """
    Test binary matrix exponentiation with fractional stepping:
    V_{k+1} = [1  1/2] * V_k
              [0   1 ]
    For N = 100, A^100 should have A[0][1] = 100 * (1/2) = 50 (exact integer).
    """
    mat = VariableCouplingMatrix(["x", "v"])
    mat.set_affine_row("x", AffineExpr({"x": 1, "v": Fraction(1, 2)}))
    mat.set_affine_row("v", AffineExpr({"v": 1}))

    pow_mat = mat.pow_mod(100)
    assert pow_mat.matrix[0][0] == 1
    assert pow_mat.matrix[0][1] == 50
    assert isinstance(pow_mat.matrix[0][1], int)
    assert pow_mat.matrix[1][1] == 1


def test_condensation_exact_rational_slave():
    """
    Test Schur static condensation with exact fractional coupling:
    Master: x_m, v_m
    Slave: s (coupled via 1/3 * x_m + 7)
    """
    mat = VariableCouplingMatrix(["x_m", "v_m", "s"])
    mat.set_affine_row("x_m", AffineExpr({"x_m": 1, "v_m": 1}))
    mat.set_affine_row("v_m", AffineExpr({"v_m": 1}))
    mat.set_affine_row("s", AffineExpr({"x_m": Fraction(1, 3)}, offset=7))

    capsule = CompositeTensorDescriptor(
        name="rational_system",
        channel_names=["x_m", "v_m", "s"],
        internal_matrix=mat,
        interface_dof=2
    )

    condensed = capsule.condense_to_interface(["x_m", "v_m"])
    assert condensed.channel_names == ["x_m", "v_m"]
    assert "s" not in condensed.channel_names
    assert "s" in condensed.recovery_map

    # Recover slave state when x_m = 300, v_m = 10
    recovered = condensed.recover_internal_state({"x_m": 300, "v_m": 10})
    # s = 1/3 * 300 + 7 = 100 + 7 = 107 (exact integer!)
    assert recovered["s"] == 107
    assert isinstance(recovered["s"], int)

    # Recover slave state when x_m is not a multiple of 3, e.g. 10
    # s = 1/3 * 10 + 7 = 10/3 + 21/3 = 31/3 (exact Fraction!)
    recovered_frac = condensed.recover_internal_state({"x_m": 10, "v_m": 10})
    assert recovered_frac["s"] == Fraction(31, 3)
    assert isinstance(recovered_frac["s"], Fraction)


def test_cross_file_resolver_fractional_defines():
    """Test CrossFileResolver evaluates fractional #define and const expressions."""
    c_code = """
    #define DT (1.0 / 60.0)
    #define SCALE (120 / 2)
    const double HALF = 1.0 / 2.0;
    """
    consts = CrossFileResolver.resolve_constants_from_c_content(c_code)
    assert consts["DT"] == Fraction(1, 60)
    assert consts["SCALE"] == 60
    assert consts["HALF"] == Fraction(1, 2)


def test_c_lifter_fractional_coupling():
    """Test C loop lifter recognizes fractional updates (e.g. x += 0.5 * v or x += v / 2)."""
    c_code = """
    void step(int N) {
        float x = 0;
        float v = 10;
        for (int i = 0; i < N; i++) {
            x += 0.5f * v;
            v += -1;
        }
    }
    """
    lifter = CLoopLifter()
    summary = lifter.lift(c_code)
    assert summary.coupling_matrix is not None
    mat = summary.coupling_matrix
    x_idx = mat.var_to_idx["x"]
    v_idx = mat.var_to_idx["v"]
    # Verify coefficient is exact Fraction(1, 2)
    assert mat.matrix[x_idx][v_idx] == Fraction(1, 2)


def test_python_lifter_fractional_scope_constant():
    """Test Python loop lifter resolves fractional constants from scope."""
    py_code = """
for i in range(100):
    x += v * DT
    v += -1
"""
    scope = {"DT": Fraction(1, 60)}
    lifter = PythonLoopLifter(scope_env=scope)
    summary = lifter.lift(py_code)
    assert summary.coupling_matrix is not None
    mat = summary.coupling_matrix
    x_idx = mat.var_to_idx["x"]
    v_idx = mat.var_to_idx["v"]
    assert mat.matrix[x_idx][v_idx] == Fraction(1, 60)


def test_affine_expr_div_and_rsub():
    """Test AffineExpr __truediv__ and __rsub__."""
    e = AffineExpr({"x": 6}, offset=9)
    # Division by int
    e2 = e / 3
    assert e2.coeffs["x"] == 2
    assert e2.offset == 3

    # Division by Fraction
    e3 = e / Fraction(3, 2)
    assert e3.coeffs["x"] == 4
    assert e3.offset == 6

    # Reverse subtraction: 20 - e = -6*x + 11
    e4 = 20 - e
    assert e4.coeffs["x"] == -6
    assert e4.offset == 11


def test_codegen_dynamic_matrix_rational_python():
    """Test Python codegen for dynamic matrix with fractions does not emit inline imports or % sl_mod."""
    from strilight.frontend.codegen import CodeGenerator
    from strilight.engine.vsa.models import LoopSummary

    summary = LoopSummary()
    mat = VariableCouplingMatrix(["x", "v"])
    mat.set_affine_row("x", AffineExpr({"x": 1, "v": Fraction(1, 2)}))
    mat.set_affine_row("v", AffineExpr({"v": 1}))
    summary.coupling_matrix = mat
    summary.symbolic_iterations = "N"

    py_code = CodeGenerator.to_python_statements(summary, N_var="N", in_place=True)
    # Ensure no dirty inline import statements inside function body
    assert "import" not in py_code
    assert "% sl_mod" not in py_code

    # Execute generated code with Fraction available in globals (as provided by SourceLifter globals injection)
    env = {"x": 0, "v": 10, "N": 5}
    exec(py_code, {"Fraction": Fraction}, env)
    # x = 0 + 5 * (1/2 * 10) = 25
    assert env["x"] == 25
    assert env["v"] == 10


def test_source_lifter_globals_injection():
    """Test that SourceLifter injects Fraction and math into globals automatically."""
    import strilight as sl

    @sl.accelerate
    def sample_frac_loop(n, x, v):
        for i in range(n):
            x += 0.5 * v
            v += 0
        return x, v

    # Function is accelerated without requiring user to import Fraction
    assert hasattr(sample_frac_loop, "_loop_summary")
    res_x, res_v = sample_frac_loop(10, 0.0, 4.0)
    # 0.0 + 10 * (0.5 * 4.0) = 20.0
    assert res_x == 20.0
    assert res_v == 4.0


def test_codegen_dynamic_matrix_rational_c():
    """Test C codegen for dynamic matrix with fractions emits double type instead of uint32_t."""
    from strilight.frontend.codegen import CodeGenerator
    from strilight.engine.vsa.models import LoopSummary

    summary = LoopSummary()
    mat = VariableCouplingMatrix(["x", "v"])
    mat.set_affine_row("x", AffineExpr({"x": 1, "v": Fraction(1, 2)}))
    mat.set_affine_row("v", AffineExpr({"v": 1}))
    summary.coupling_matrix = mat
    summary.symbolic_iterations = "N"

    c_code = CodeGenerator.to_c_statements(summary, N_var="N", in_place=True)
    assert "double sl_base" in c_code
    assert "double sl_res" in c_code
    assert "double final_x" in c_code


def test_python_lifter_single_var_fractional_stride():
    """Test Python lifter extracts fractional stride for single variable without truncation."""
    import strilight as sl

    @sl.accelerate
    def step_single_var(n, x):
        for i in range(n):
            x += 0.5
        return x

    assert hasattr(step_single_var, "_loop_summary")
    res = step_single_var(10, 0.0)
    # 0.0 + 10 * 0.5 = 5.0
    assert res == 5.0
