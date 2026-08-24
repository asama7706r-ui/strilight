"""
Test Suite verifying Notion Strided Interval Domain & Reduced Product Theorems:
- Commutative GCD Join (sqcup^#)
- Stride-to-Mask Reduced Product Deduction
- Sub-register Physics (Zero-Extension & Blending)
- Aliasing Pruning Rules
- VSA Evaluator Sub-register Simulation & IMUL Instruction Dispatch
"""

import math
import pytest
from strilight.pruning.interval import StridedInterval, Interval, DisjointIntervalSet
from strilight.engine.abstract_state import AbstractState
from strilight.engine.vsa_evaluator import LoopEvaluator
from strilight.engine.loop_compressor import LoopBlock
from strilight.engine.tracker import TraceRecord


def create_mock_record(tick, addr, mnemonic, op_str, size=4):
    return TraceRecord(tick=tick, address=addr, size=size, mnemonic=mnemonic, op_str=op_str)


# ==============================================================================
# TEST 1: Commutative GCD Join (sqcup^#)
# ==============================================================================
def test_commutative_join_linear():
    """
    Verifies that joining [10, 22] and [2, 6] produces [2, 22] symmetrically without exploding to Top.
    """
    i1 = Interval(10, 22, bit_width=64, stride=4)
    i2 = Interval(2, 6, bit_width=64, stride=4)
    
    # 1. Join S1 cup S2
    j1 = i1.join(i2)
    assert j1.min_val == 2
    assert j1.max_val == 22
    assert j1.stride == 4
    assert not j1.is_circular
    
    # 2. Join S2 cup S1 (Commutativity)
    j2 = i2.join(i1)
    assert j2.min_val == 2
    assert j2.max_val == 22
    assert j2.stride == 4
    assert not j2.is_circular
    assert j1.min_val == j2.min_val and j1.max_val == j2.max_val and j1.stride == j2.stride


def test_gcd_bridge_in_join():
    """
    Verifies that s_new = gcd(s1, s2, |m1 - m2|).
    """
    # m1 = 10, m2 = 26 (diff = 16), s1 = 8, s2 = 8 -> gcd(8, 8, 16) = 8
    i1 = Interval(10, 18, stride=8)
    i2 = Interval(26, 34, stride=8)
    j = i1.join(i2)
    assert j.min_val == 10
    assert j.max_val == 34
    assert j.stride == 8

    # m1 = 10, m2 = 25 (diff = 15), s1 = 8, s2 = 8 -> gcd(8, 8, 15) = 1
    i3 = Interval(25, 33, stride=8)
    j_diff = i1.join(i3)
    assert j_diff.stride == 1


# ==============================================================================
# TEST 2: Stride to Mask Reduced Product Deduction
# ==============================================================================
def test_stride_to_mask_deduction():
    """
    Notion Section 4.a: If stride s = 2^k, lowest k bits are guaranteed known.
    """
    # s = 8 = 2^3, base = 0x1000 (lowest 3 bits are 000)
    i1 = Interval(0x1000, 0x2000, stride=8)
    assert (i1.known_mask & 0x7) == 0x7
    assert (i1.known_value & 0x7) == 0x0

    # s = 16 = 2^4, base = 0x1005 (lowest 4 bits are 0101 = 5)
    i2 = Interval(0x1005, 0x2005, stride=16)
    assert (i2.known_mask & 0xF) == 0xF
    assert (i2.known_value & 0xF) == 0x5


# ==============================================================================
# TEST 3: Sub-register Physics (Zero-Extension & Blending)
# ==============================================================================
def test_subregister_zero_extend():
    """
    Notion Section 4.b: 32-bit writes zero-extend to 64-bit and set top 32 bits to 0.
    """
    i32 = Interval(0x12345678, 0x12345678, bit_width=32)
    i64 = i32.zero_extend(src_bit_width=32, dst_bit_width=64)
    
    assert i64.bit_width == 64
    assert i64.min_val == 0x12345678
    assert i64.max_val == 0x12345678
    # Top 32 bits must be known zeros
    assert (i64.known_mask & 0xFFFFFFFF00000000) == 0xFFFFFFFF00000000
    assert (i64.known_value & 0xFFFFFFFF00000000) == 0x0


def test_subregister_blend():
    """
    Notion Section 4.b: 8-bit/16-bit writes blend into the base register preserving untouched bits.
    """
    rax_iv = Interval(0x1122334455667788, 0x1122334455667788, bit_width=64)
    al_iv = Interval(0xAA, 0xAA, bit_width=64)
    
    blended = rax_iv.blend(al_iv, bit_mask=0xFF)
    assert blended.min_val == 0x11223344556677AA
    assert blended.max_val == 0x11223344556677AA

    # Blend AX (16-bit)
    ax_iv = Interval(0xBBCC, 0xBBCC, bit_width=64)
    blended_ax = rax_iv.blend(ax_iv, bit_mask=0xFFFF)
    assert blended_ax.min_val == 0x112233445566BBCC


# ==============================================================================
# TEST 4: Aliasing Rules (Must-Alias & Definite Non-Alias)
# ==============================================================================
def test_aliasing_rules():
    """
    Notion Section 8.b:
    1. Definite Non-Alias: Modulo Congruence Disjointness or Linear Non-Overlap
    2. Must-Alias: Identical Bounds and Stride
    """
    # Even pointer vs Odd pointer
    p_even = Interval(0x1000, 0x2000, stride=8) # addresses mod 8 == 0
    p_odd = Interval(0x1004, 0x2004, stride=8)  # addresses mod 8 == 4
    
    assert p_even.is_definite_non_alias(p_odd) is True
    assert p_even.is_must_alias(p_odd) is False
    
    p_even_clone = Interval(0x1000, 0x2000, stride=8)
    assert p_even.is_must_alias(p_even_clone) is True
    assert p_even.is_definite_non_alias(p_even_clone) is False


# ==============================================================================
# TEST 5: VSA Evaluator Sub-register Simulation & IMUL
# ==============================================================================
def test_vsa_evaluator_subregister_and_imul():
    """
    Tests LoopEvaluator executing x86 instructions with subregister physics and imul.
    """
    evaluator = LoopEvaluator()
    
    # 1. Test AL write preserving upper RAX bits
    state = AbstractState()
    rax_dset = DisjointIntervalSet(k_limit=8)
    rax_dset.add(Interval(0x1122334455667788, 0x1122334455667788, bit_width=64))
    state.set_register('rax', rax_dset)
    
    rec_al = create_mock_record(1, 0x1000, "mov", "al, 0xAA", size=1)
    evaluator._dispatch_instruction(rec_al, state)
    
    rax_after_al = state.get_register('rax')
    assert rax_after_al is not None
    assert rax_after_al.intervals[0].min_val == 0x11223344556677AA
    
    # 2. Test EAX write zero-extending RAX
    rec_eax = create_mock_record(2, 0x1004, "mov", "eax, 0x55", size=4)
    evaluator._dispatch_instruction(rec_eax, state)
    
    rax_after_eax = state.get_register('rax')
    assert rax_after_eax is not None
    assert rax_after_eax.intervals[0].min_val == 0x0000000000000055
    
    # 3. Test IMUL instruction evaluation
    rec_imul = create_mock_record(3, 0x1008, "imul", "eax, 4", size=4)
    evaluator._dispatch_instruction(rec_imul, state)
    
    rax_after_imul = state.get_register('eax')
    assert rax_after_imul is not None
    assert rax_after_imul.intervals[0].min_val == 0x55 * 4
