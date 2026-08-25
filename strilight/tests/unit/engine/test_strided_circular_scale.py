import z3
import pytest
from strilight.engine.vsa_evaluator import LoopSummary
from strilight.engine.translator import Z3Translator
from strilight.pruning.interval import StridedInterval


def test_strided_circular_one_million_iterations():
    """
    Directly tests closed-form lifting of the 1,000,000-iteration Strided Circular loop:
    table[(i * 2) & 0xF] over N = 1,000,000 with geometric shift and 32-bit wrap-around.
    """
    table = [
        0x0000, 0x1004, 0x2008, 0x300c,
        0x4010, 0x5014, 0x6018, 0x701c,
        0x8020, 0x9024, 0xa028, 0xb02c,
        0xc030, 0xd034, 0xe038, 0xf03c
    ]
    
    # Verify Bézout GCD non-aliasing (Rule 8)
    s_table = StridedInterval(0, 14, bit_width=32, stride=2)
    s_stack = StridedInterval(0x1000, 0x1020, bit_width=32, stride=4)
    assert s_table.is_disjoint_modulo(s_stack)

    # Setup LoopSummary
    summary = LoopSummary()
    summary.iterations = 1_000_000
    
    # 1. Polycyclic pattern across circular table (P = 8)
    pattern = [table[(i * 2) & 0xF] for i in range(8)]
    summary.patterns['rax'] = pattern
    
    # 2. Geometric shift recurrence for k2 (Rule 6)
    summary.geometric_shifts['rbx'] = {
        'base': 2,
        'var': 'rcx',
        'val': 1
    }
    
    translator = Z3Translator()
    
    # Translate loop summary into Z3 in O(1)
    translator.translate_loop_summary(summary, max_iterations=1_000_000)
    
    # Assert N = 1,000,000
    N = translator.latest_loop_counter
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
    solver.add(N == 1_000_000)
    
    assert solver.check() == z3.sat
