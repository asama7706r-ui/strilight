"""
Mathematical Stress-Test Suite for Circular Strided Intervals & Whitepaper Theorems.
Tests all core theorems against concrete exhaustive ground-truth simulations in finite rings (Z / 2^w Z).
"""

import math
import pytest


def circular_contains(x: int, m: int, M: int, s: int, w: int = 8) -> bool:
    mod = 1 << w
    length = (M - m) % mod
    dist = (x - m) % mod
    if s == 0:
        return dist == 0
    return dist <= length and (dist % s == 0)


# ==============================================================================
# TEST 1: Newton 2nd-Degree Induction under Massive Multi-Wrap Overflow
# ==============================================================================
def test_newton_series_under_circular_overflow():
    """
    Stress-tests Newton quadratic formula:
    State(N) = State_0 + N * Delta_1 + N*(N-1)/2 * Delta_2 (mod 2^w)
    against an actual step-by-step concrete CPU loop executing 100,000 iterations.
    """
    w = 16  # 16-bit ring: mod 65536
    mod = 1 << w
    
    # Quadratic sequence: x_{n+1} = x_n + 3*n + 7
    # Delta_1_0 = 7, Delta_2 = 3
    state_0 = 1234
    delta_1 = 7
    delta_2 = 3
    
    # 1. Concrete simulation of 10,000 iterations on CPU (wrapping every few iterations)
    N = 10000
    current = state_0
    for i in range(N):
        step_add = (delta_1 + i * delta_2) % mod
        current = (current + step_add) % mod
        
    concrete_final = current
    
    # 2. Mathematical Closed-Form Newton Formula modulo 2^w
    # Note: N*(N-1)//2 must be computed in unbounded integers before modulo 2^w
    newton_final = (state_0 + N * delta_1 + (N * (N - 1) // 2) * delta_2) % mod
    
    assert newton_final == concrete_final, f"Newton mismatch: {newton_final} != {concrete_final}"


# ==============================================================================
# TEST 2: Positional Horner Receipt for Bit-Extraction under 64-bit Overflow
# ==============================================================================
def test_positional_horner_under_modular_wrap():
    """
    Stress-tests Horner positional receipt x = 2*x + bit_i
    when bit length exceeds 64 bits and high bits are discarded by CPU register.
    """
    w = 64
    mod = 1 << 64
    
    # 128-bit key (so it overflows 64-bit register multiple times)
    test_key_128 = 0xDEADBEEFCAFEBABE1337C0DEDEADBEEF
    
    # 1. Concrete step-by-step simulation (128 iterations)
    x_concrete = 0
    for i in range(128):
        bit = (test_key_128 >> (127 - i)) & 1
        x_concrete = ((x_concrete * 2) + bit) % mod
        
    # 2. Positional Formula: Sum(bit_i * 2^(127 - i)) mod 2^64
    # The lowest 64 bits of test_key_128 must match x_concrete!
    expected_low_64 = test_key_128 % mod
    
    assert x_concrete == expected_low_64, f"Horner 64-bit truncation failed: {hex(x_concrete)} != {hex(expected_low_64)}"


# ==============================================================================
# TEST 3: Telescoping Cascade with Overflowing Branch Actions
# ==============================================================================
def test_telescoping_cascade_with_overflowing_deltas():
    """
    Stress-tests 4-branch cascade where branches perform large additions that wrap around.
    Verifies Partition of Unity and exact value recovery under all boolean assignments.
    """
    w = 8
    mod = 256
    
    # 4 distinct deltas, some exceeding 256
    deltas = [250, 130, 200, 15]  # in mod 256: [-6, -126, -56, 15]
    
    # Test all possible branch decision states
    # Case 1: c_A = 1 (Choice 1) -> Expected: deltas[0] % 256
    # Case 2: c_A = 0, c_B = 1 (Choice 2) -> Expected: deltas[1] % 256
    # Case 3: c_A = 0, c_B = 0, c_C = 1 (Choice 3) -> Expected: deltas[2] % 256
    # Case 4: c_A = 0, c_B = 0, c_C = 0 (Choice 4) -> Expected: deltas[3] % 256
    
    test_cases = [
        ((1, 0, 0), deltas[0] % mod),
        ((0, 1, 0), deltas[1] % mod),
        ((0, 0, 1), deltas[2] % mod),
        ((0, 0, 0), deltas[3] % mod),
    ]
    
    for (cA, cB, cC), expected in test_cases:
        P1 = cA
        P2 = (1 - cA) * cB
        P3 = (1 - cA) * (1 - cB) * cC
        P4 = (1 - cA) * (1 - cB) * (1 - cC)
        
        # Partition of Unity Check
        assert (P1 + P2 + P3 + P4) == 1
        
        # Total Delta modulo 256
        delta_total = (P1 * deltas[0] + P2 * deltas[1] + P3 * deltas[2] + P4 * deltas[3]) % mod
        assert delta_total == expected, f"Failed for ({cA},{cB},{cC}): {delta_total} != {expected}"


# ==============================================================================
# TEST 4: Memory Aliasing & Modular GCD Disjointness on Circular Pointers
# ==============================================================================
def test_circular_memory_aliasing_modulo_disjointness():
    """
    Stress-tests two pointer intervals that wrap across memory boundary (e.g. top of stack).
    Verifies that GCD modulo congruence:
    m1 != m2 (mod gcd(s1, s2))
    guarantees ZERO overlap even when pointers wrap around 0.
    """
    w = 8
    mod = 256
    
    # Read pointer: Even addresses wrapping around 0: {250, 252, 254, 0, 2, 4} (step 2)
    s1, m1, M1 = 2, 250, 4
    
    # Write pointer: Odd addresses wrapping around 0: {251, 253, 255, 1, 3, 5} (step 2)
    s2, m2, M2 = 2, 251, 5
    
    # Concrete set of elements
    read_elements = {x for x in range(mod) if circular_contains(x, m1, M1, s1, w)}
    write_elements = {x for x in range(mod) if circular_contains(x, m2, M2, s2, w)}
    
    # Ground Truth: Are they disjoint?
    concrete_overlap = read_elements & write_elements
    assert len(concrete_overlap) == 0, "Concrete sets should be completely disjoint!"
    
    # Theorem Check: Modular Congruence Disjointness
    g = math.gcd(s1, s2)  # gcd(2, 2) = 2
    # m1 % g != m2 % g (250 % 2 == 0 != 251 % 2 == 1)
    is_provably_disjoint = (m1 % g) != (m2 % g)
    
    assert is_provably_disjoint is True, "GCD congruence failed to prove disjointness of wrapping pointers!"


# ==============================================================================
# TEST 5: Circular Multiplication & Stride Preservation
# ==============================================================================
def test_circular_multiplication_stride_preservation():
    """
    Tests multiplication of a circular interval by an integer constant:
    S_new = (s * k)[ (m * k) mod 2^w  ->  (M * k) mod 2^w ]
    """
    w = 8
    mod = 256
    
    # S = {254, 0, 2, 4} (step 2, spans 0)
    s, m, M = 2, 254, 4
    k = 3  # multiply by 3
    
    concrete_S = {x for x in range(mod) if circular_contains(x, m, M, s, w)}
    concrete_mult = {(x * k) % mod for x in concrete_S}
    
    # Multiplied elements: { (254*3)%256 = 250, (0*3)%256 = 0, (2*3)%256 = 6, (4*3)%256 = 12 }
    # Step should be s * gcd(k, mod) = 2 * gcd(3, 256) = 2 * 1 = 6 (in modular step)
    s_new = (s * k) % mod
    m_new = (m * k) % mod  # 250
    M_new = (M * k) % mod  # 12
    
    predicted_elements = {x for x in range(mod) if circular_contains(x, m_new, M_new, s_new, w)}
    
    assert concrete_mult.issubset(predicted_elements), "Multiplication lost soundness!"
