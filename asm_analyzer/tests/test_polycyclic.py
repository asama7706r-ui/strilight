import sys
import os
import pytest
import z3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import LoopBlock
from asm_analyzer.engine.vsa_evaluator import LoopEvaluator, LoopSummary
from asm_analyzer.engine.translator import Z3Translator

def create_mock_record(tick, addr, mnemonic, op_str):
    return TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)

def test_polycyclic_pattern_extraction_4():
    """
    Test that LoopEvaluator extracts a 4-step polycyclic pattern: [+5, +4, +8, +1]
    Constructed by an inner loop or sequence of operations.
    """
    inner_body = [
        create_mock_record(1, 0x1000, "add", "eax, 5"),
        create_mock_record(2, 0x1004, "add", "eax, 4"),
        create_mock_record(3, 0x1008, "add", "eax, 8"),
        create_mock_record(4, 0x100C, "add", "eax, 1"),
        create_mock_record(5, 0x1010, "cmp", "ecx, 100"),
        create_mock_record(6, 0x1014, "jle", "0x1000")
    ]
    
    loop_block = LoopBlock(body=inner_body, iterations=100)
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(loop_block)
    
    # The sum of one iteration of this macro-block is 5 + 4 + 8 + 1 = 18
    assert "eax" in summary.deltas
    assert summary.deltas["eax"] == 18

def test_polycyclic_pattern_direct():
    """
    Test direct polycyclic pattern extraction when an inner loop has a pattern.
    """
    summary = LoopSummary()
    summary.patterns["rax"] = [5, 4, 8, 1]
    
    translator = Z3Translator()
    translator.translate_loop_summary(summary, max_iterations=100)
    
    # Query Z3: If N = 7, what is rax?
    # Cycle sum = 5 + 4 + 8 + 1 = 18 (P=4)
    # For N = 7: Q = 7 // 4 = 1, R = 7 % 4 = 3
    # Base delta = 1 * 18 = 18
    # Remainder delta (first 3): 5 + 4 + 8 = 17
    # Total delta = 18 + 17 = 35
    
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    N = translator.latest_loop_counter
    rax_var = translator.reg_state['rax']
    
    # Fix N = 7 and solve for rax
    solver.add(N == 7)
    assert solver.check() == z3.sat
    m = solver.model()
    rax_val = m.eval(rax_var).as_long()
    assert rax_val == 35

def test_polycyclic_z3_solve_exact_n():
    """
    Test that Z3 can solve backward for the exact N given a target rax value in a polycyclic loop!
    Target: rax reaches 89.
    Pattern: [5, 4, 8, 1], P = 4, Sum = 18.
    For N=19: Q=4, R=3 -> 4*18 + (5+4+8) = 72 + 17 = 89.
    """
    summary = LoopSummary()
    summary.patterns["rax"] = [5, 4, 8, 1]
    
    translator = Z3Translator()
    translator.translate_loop_summary(summary, max_iterations=100)
    
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    N = translator.latest_loop_counter
    rax_var = translator.reg_state['rax']
    rax_initial = z3.BitVec('rax_t0', 64)
    
    # Require initial rax == 0 and final rax == 89
    solver.add(rax_initial == 0)
    solver.add(rax_var == 89)
    assert solver.check() == z3.sat
    m = solver.model()
    solved_n = m.eval(N).as_long()
    assert solved_n == 19

def test_polycyclic_nested_loop_closed_form():
    """
    Test nested loop where inner loop has a polycyclic pattern and outer loop applies it.
    """
    # Inner loop with pattern [10, 20], P = 2, Sum = 30
    inner_summary = LoopSummary()
    inner_summary.patterns["rbx"] = [10, 20]
    
    # Inner loop ran 5 times: Q=2, R=1 -> Delta = 2*30 + 10 = 70
    P = len(inner_summary.patterns["rbx"])
    N_inner = 5
    Q = N_inner // P
    R = N_inner % P
    expected_inner_delta = Q * sum(inner_summary.patterns["rbx"]) + sum(inner_summary.patterns["rbx"][:R])
    assert expected_inner_delta == 70

def test_polycyclic_memory_pattern():
    """
    Test polycyclic pattern on a memory location MEM_20480_32.
    """
    summary = LoopSummary()
    summary.patterns["MEM_20480_32"] = [2, 3, 5]
    
    translator = Z3Translator()
    translator.translate_loop_summary(summary, max_iterations=100)
    
    # For N = 5:
    # Pattern [2, 3, 5], P = 3, Sum = 10
    # Q = 5 // 3 = 1, R = 5 % 3 = 2
    # Base = 1 * 10 = 10
    # Extra (first 2): 2 + 3 = 5
    # Total = 15
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    N = translator.latest_loop_counter
    solver.add(N == 5)
    assert solver.check() == z3.sat

if __name__ == "__main__":
    pytest.main(["-v", "-s", __file__])
