import z3
import pytest
from strilight.engine.vsa_evaluator import LoopSummary
from strilight.engine.translator import Z3Translator


def test_geometric_shift_summary_translation():
    """
    Tests Rule 6 from Notion (Positional Weighted Receipt / Geometric Shift Recurrence):
    acc = acc + (k2 << i) across N iterations -> acc_N = acc_0 + ((2^N - 1) * k2)
    """
    summary = LoopSummary()
    summary.iterations = 10
    
    # Inject geometric shift contract for rax (acc) accumulating rbx (k2)
    summary.geometric_shifts['rax'] = {
        'base': 2,
        'var': 'rbx',
        'val': 1
    }
    
    # Create Z3 translator
    translator = Z3Translator()
    
    # Set initial state: rax = 0x100, rbx = 5
    translator.solver.add(translator._get_phys_reg('rax') == 0x100)
    translator.solver.add(translator._get_phys_reg('rbx') == 5)
    
    # Translate loop summary into Z3 in O(1)
    translator.translate_loop_summary(summary, max_iterations=100)
    
    # Query: What is rax when N = 10?
    N = translator.latest_loop_counter
    rax_var = translator.reg_state['rax']
    
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    solver.add(N == 10)
    
    assert solver.check() == z3.sat
    m = solver.model()
    
    # Expected result: 0x100 + ((2^10 - 1) * 5) = 256 + (1023 * 5) = 256 + 5115 = 5371
    assert m[rax_var].as_long() == 5371


def test_geometric_shift_symbolic_solving():
    """
    Tests solving for the unknown secret key (rbx) given a target final accumulator value
    over 50 iterations with zero loop unrolling (O(1) closed-form lifting).
    """
    summary = LoopSummary()
    summary.geometric_shifts['rax'] = {
        'base': 2,
        'var': 'rbx',
        'val': 1
    }
    
    translator = Z3Translator()
    
    # Set initial rax = 0 BEFORE translating the loop
    rax_init = translator._get_phys_reg('rax')
    rbx_init = translator._get_phys_reg('rbx')
    translator.solver.add(rax_init == 0)
    
    translator.translate_loop_summary(summary, max_iterations=100)
    
    N = translator.latest_loop_counter
    rax_final = translator.reg_state['rax']
    
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    # Loop runs for N = 8 iterations
    # Goal: rax == (2^8 - 1) * secret_key = 255 * 1337 = 340935
    solver.add(N == 8)
    solver.add(rax_final == 340935)
    
    assert solver.check() == z3.sat
    m = solver.model()
    recovered_key = m[rbx_init].as_long()
    assert recovered_key == 1337
