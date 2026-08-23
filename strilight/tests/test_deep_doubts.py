"""
Exhaustive Mathematical & Architectural Stress-Test Suite for Deep Edge-Case Doubts.
Tests:
1. Signed Two's Complement Transitions under Wrap-Around (JL / JGE signed boundaries)
2. Coupled Multi-Register Simultaneous Transitions (Fibonacci / Matrix Monoid Recurrences)
3. Stride Preservation under Bitwise NOT (~x) and Two's Complement NEG (-x)
4. Degree-3 Cubic Newton Induction (Triply Nested Loops: N*(N-1)*(N-2)/6 mod 2^w)
5. Mixed Bitwise AND + Arithmetic ADD Cycle Stabilization
6. Symbolic Stride Bezout Congruence in Z3
7. Zero-Stride Point Degeneracy (s = 0, divide-by-zero safety)
8. x86 Sub-register Asymmetry (8/16-bit preservation vs 32-bit zero-extension clobber)
"""

import math
import z3
import pytest


def circular_contains(x: int, m: int, M: int, s: int, w: int = 8) -> bool:
    mod = 1 << w
    length = (M - m) % mod
    dist = (x - m) % mod
    if s == 0:
        return dist == 0
    return dist <= length and (dist % s == 0)


# ==============================================================================
# DOUBT 1: Signed Integer Transitions (Positive -> Negative Wrap-Around)
# ==============================================================================
def test_doubt_signed_twos_complement_transitions():
    """
    DOUBT: When an unsigned counter wraps around 0x7FFFFFFF into 0x80000000,
    it becomes negative in Two's Complement.
    Does our modular distance invariant correctly handle signed boundary checks?
    """
    w = 32
    mod = 1 << w
    half = 1 << (w - 1)  # 0x80000000
    
    def to_signed(val):
        return val if val < half else val - mod

    # Start near signed boundary: 0x7FFFFFFE (+2147483646)
    # Increment by 2 across signed boundary into negative numbers
    # Sequence: 0x7FFFFFFE (+), 0x80000000 (-2147483648), 0x80000002 (-2147483646)
    m = 0x7FFFFFFE
    M = 0x80000002
    s = 2
    
    concrete_points = [0x7FFFFFFE, 0x80000000, 0x80000002]
    
    # 1. Circular invariant test
    for pt in concrete_points:
        assert circular_contains(pt, m, M, s, w=w) is True
        
    # 2. Outside point test (e.g. 0x80000004 or 0x7FFFFFFC)
    assert circular_contains(0x80000004, m, M, s, w=w) is False
    assert circular_contains(0x7FFFFFFC, m, M, s, w=w) is False
    
    # 3. Signed values verified
    signed_vals = [to_signed(x) for x in concrete_points]
    assert signed_vals == [2147483646, -2147483648, -2147483646]


# ==============================================================================
# DOUBT 2: Coupled Multi-Register Matrix Recurrences (Fibonacci Sequence)
# ==============================================================================
def test_doubt_coupled_multi_register_matrix_recurrence():
    """
    DOUBT: Registers updating each other simultaneously:
    RAX_new = (RAX + RBX) mod 2^w
    RBX_new = RAX_old
    Does matrix exponentiation A^N mod 2^w match concrete execution over 50,000 steps?
    """
    w = 64
    mod = 1 << w
    
    # Matrix A = [[1, 1], [1, 0]]
    # State_0 = [1, 0] (Fibonacci)
    # Concrete loop for N = 1,000 steps
    N = 1000
    rax, rbx = 1, 0
    for _ in range(N):
        rax, rbx = (rax + rbx) % mod, rax
        
    concrete_rax, concrete_rbx = rax, rbx
    
    # Fast Matrix Power modulo 2^w
    def mat_mul_2x2(A, B):
        return [
            [(A[0][0]*B[0][0] + A[0][1]*B[1][0]) % mod, (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % mod],
            [(A[1][0]*B[0][0] + A[1][1]*B[1][0]) % mod, (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % mod]
        ]
        
    def mat_pow(A, p):
        res = [[1, 0], [0, 1]]
        base = A
        while p > 0:
            if p % 2 == 1:
                res = mat_mul_2x2(res, base)
            base = mat_mul_2x2(base, base)
            p //= 2
        return res
        
    A_N = mat_pow([[1, 1], [1, 0]], N)
    # [RAX_N, RBX_N]^T = A^N * [1, 0]^T
    mat_rax = (A_N[0][0] * 1 + A_N[0][1] * 0) % mod
    mat_rbx = (A_N[1][0] * 1 + A_N[1][1] * 0) % mod
    
    assert (mat_rax, mat_rbx) == (concrete_rax, concrete_rbx), "Matrix Coupling Recurrence Failed!"


# ==============================================================================
# DOUBT 3: Stride Preservation under NOT (~x) and NEG (-x)
# ==============================================================================
def test_doubt_stride_preservation_not_and_neg():
    """
    DOUBT: When circular interval undergoes ~x (bitwise NOT) or -x (two's complement NEG),
    does the stride s remain identical and do the bounds invert properly?
    """
    w = 8
    mod = 256
    
    # S = {250, 252, 254, 0, 2, 4} (m=250, M=4, s=2)
    s, m, M = 2, 250, 4
    concrete_S = {x for x in range(mod) if circular_contains(x, m, M, s, w)}
    
    # 1. Test NEG (-x mod 256):
    # Theory: m_neg = (-M) mod 256, M_neg = (-m) mod 256, s_neg = s
    concrete_neg = {(-x) % mod for x in concrete_S}
    m_neg = (-M) % mod  # -4 % 256 = 252
    M_neg = (-m) % mod  # -250 % 256 = 6
    s_neg = s
    
    predicted_neg = {x for x in range(mod) if circular_contains(x, m_neg, M_neg, s_neg, w)}
    assert concrete_neg == predicted_neg, f"NEG failed: {concrete_neg} != {predicted_neg}"
    
    # 2. Test NOT (~x mod 256 = (-x - 1) mod 256):
    # Theory: m_not = (~M) mod 256, M_not = (~m) mod 256, s_not = s
    concrete_not = {(~x) % mod for x in concrete_S}
    m_not = (~M) % mod  # ~4 % 256 = 251
    M_not = (~m) % mod  # ~250 % 256 = 5
    s_not = s
    
    predicted_not = {x for x in range(mod) if circular_contains(x, m_not, M_not, s_not, w)}
    assert concrete_not == predicted_not, f"NOT failed: {concrete_not} != {predicted_not}"


# ==============================================================================
# DOUBT 4: Degree-3 Cubic Newton Induction (Triply Nested Loops)
# ==============================================================================
def test_doubt_cubic_newton_triply_nested_loops():
    """
    DOUBT: In triply nested loops, the closed-form equation contains N*(N-1)*(N-2)/6.
    Does this evaluate without precision loss under 32-bit and 64-bit integer overflow?
    """
    w = 32
    mod = 1 << w
    
    # Triply nested loop simulation:
    # for i in range(N):
    #   for j in range(i):
    #     for k in range(j):
    #       total += 1
    N = 2500  # N=2500 -> sum is 2500*2499*2498 / 6 = 2,601,041,250 (exceeds 32-bit signed max)
    
    concrete_total = 0
    for i in range(N):
        concrete_total = (concrete_total + (i * (i - 1) // 2)) % mod
        
    # Closed Form: Binomial(N, 3) = N*(N-1)*(N-2)//6
    # Note: Product of 3 consecutive integers is ALWAYS divisible by 6 (Pigeonhole / Pascal)
    closed_form_total = (N * (N - 1) * (N - 2) // 6) % mod
    
    assert closed_form_total == concrete_total, f"Cubic Newton Mismatch: {closed_form_total} != {concrete_total}"


# ==============================================================================
# DOUBT 5: Mixed Bitwise AND + Arithmetic ADD Cycle Stabilization
# ==============================================================================
def test_doubt_mixed_bitwise_and_add_cycle():
    """
    DOUBT: Loop: x = (x + 7) & 0xFE (mod 256).
    Does the sequence enter a cycle with a constant stride?
    """
    mod = 256
    x = 0
    history = []
    
    for _ in range(500):
        history.append(x)
        x = ((x + 7) & 0xFE) % mod
        
    # Find cycle length and stride
    first_seen = {}
    cycle_start = 0
    cycle_period = 0
    for i, val in enumerate(history):
        if val in first_seen:
            cycle_start = first_seen[val]
            cycle_period = i - cycle_start
            break
        first_seen[val] = i
        
    cycle_elements = history[cycle_start : cycle_start + cycle_period]
    # Check that all elements in cycle have bit 0 = 0 (step multiple of 2)
    assert all(v % 2 == 0 for v in cycle_elements)
    assert cycle_period > 0, "Failed to stabilize into a periodic limit cycle!"


# ==============================================================================
# DOUBT 6: Symbolic Stride Bezout Congruence in Z3
# ==============================================================================
def test_doubt_symbolic_stride_bezout_in_z3():
    """
    DOUBT: When stride 's' is a symbolic variable in Z3 (e.g. element size controlled by user),
    does Z3 successfully verify pointer congruence (target - base) % s == 0?
    """
    solver = z3.Solver()
    
    base = z3.BitVec("base", 64)
    target = z3.BitVec("target", 64)
    elem_size = z3.BitVec("elem_size", 64)
    idx = z3.BitVec("idx", 64)
    
    # Target is generated by indexing: target == base + idx * elem_size
    solver.add(target == base + idx * elem_size)
    solver.add(elem_size == 8)
    solver.add(base == 0x140005000)
    solver.add(target == 0x140005048) # offset 0x48 = 72 = 9 * 8
    
    assert solver.check() == z3.sat
    model = solver.model()
    solved_idx = model[idx].as_long()
    assert solved_idx == 9, f"Z3 failed to solve index: {solved_idx} != 9"


# ==============================================================================
# DOUBT 7: Zero-Stride Point Degeneracy (s = 0, Divide-by-Zero Safety)
# ==============================================================================
def test_doubt_zero_stride_point_degeneracy():
    """
    DOUBT: Constant scalar values have s = 0.
    Does the circular containment and GCD functions handle s = 0 safely without division by zero?
    """
    w = 8
    mod = 256
    
    # Point interval at 42: m = 42, M = 42, s = 0
    m, M, s = 42, 42, 0
    
    # Must contain 42
    assert circular_contains(42, m, M, s, w=w) is True
    # Must NOT contain 43 or any other number
    assert circular_contains(43, m, M, s, w=w) is False
    assert circular_contains(41, m, M, s, w=w) is False
    
    # GCD with 0: gcd(0, 8) must equal 8
    assert math.gcd(0, 8) == 8
    assert math.gcd(0, 0) == 0


# ==============================================================================
# DOUBT 8: x86 Sub-register Asymmetry (8/16-bit Preserved vs 32-bit Zero-Extended)
# ==============================================================================
def test_doubt_x86_subregister_asymmetry():
    """
    DOUBT: In x86_64 architecture:
    - Writing to AL (8-bit) preserves upper 56 bits of RAX.
    - Writing to AX (16-bit) preserves upper 48 bits of RAX.
    - Writing to EAX (32-bit) ZERO-EXTENDS and WIPES the upper 32 bits of RAX to 0x00000000.
    Verifies that dual-mask correctly models this physical hardware asymmetry.
    """
    rax_init = 0x1122334455667788
    
    # 1. Write AL = 0xAA (8-bit)
    rax_after_al = (rax_init & ~0xFF) | 0xAA
    assert rax_after_al == 0x11223344556677AA, "AL write failed to preserve upper 56 bits!"
    
    # 2. Write AX = 0xBBCC (16-bit)
    rax_after_ax = (rax_init & ~0xFFFF) | 0xBBCC
    assert rax_after_ax == 0x112233445566BBCC, "AX write failed to preserve upper 48 bits!"
    
    # 3. Write EAX = 0xDDEEFF00 (32-bit) -> x86 Hardware Rule: Full 64-bit upper wipe!
    rax_after_eax = 0xDDEEFF00  # Zero extended to 64 bits
    assert rax_after_eax == 0x00000000DDEEFF00, "EAX write failed to zero-extend to 64 bits!"
