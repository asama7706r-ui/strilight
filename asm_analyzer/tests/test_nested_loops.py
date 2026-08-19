import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import TraceCompressor, LoopBlock

def create_mock_record(tick, addr, mnemonic="add", op_str="eax, 1"):
    record = TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)
    # Basic mock parser for test purposes
    ops = [o.strip() for o in op_str.split(",")] if op_str else []
    for i, op in enumerate(ops):
        is_dest = (i == 0)
        if op.isdigit():
            record.operands.append({'type': 'imm', 'value': int(op)})
        else:
            record.operands.append({'type': 'reg', 'value': op})
            if is_dest:
                record.regs_write.append(op)
            else:
                record.regs_read.append(op)
    return record

def test_trace_compressor_nested_loops():
    # Outer Loop (0x1000, 0x1004) iterates 2 times
    # Inner Loop (0x2000, 0x2004) iterates 3 times
    trace = [
        # --- Outer Iteration 1 ---
        create_mock_record(1, 0x1000, "mov", "ecx, 0"),
        create_mock_record(2, 0x2000, "add", "eax, 1"),
        create_mock_record(3, 0x2004, "cmp", "eax, 10"),
        create_mock_record(4, 0x2000, "add", "eax, 1"),
        create_mock_record(5, 0x2004, "cmp", "eax, 10"),
        create_mock_record(6, 0x2000, "add", "eax, 1"),
        create_mock_record(7, 0x2004, "cmp", "eax, 10"),
        create_mock_record(8, 0x1004, "cmp", "ecx, 5"),
        
        # --- Outer Iteration 2 ---
        create_mock_record(9, 0x1000, "mov", "ecx, 0"),
        create_mock_record(10, 0x2000, "add", "eax, 1"),
        create_mock_record(11, 0x2004, "cmp", "eax, 10"),
        create_mock_record(12, 0x2000, "add", "eax, 1"),
        create_mock_record(13, 0x2004, "cmp", "eax, 10"),
        create_mock_record(14, 0x2000, "add", "eax, 1"),
        create_mock_record(15, 0x2004, "cmp", "eax, 10"),
        create_mock_record(16, 0x1004, "cmp", "ecx, 5"),
    ]
    
    compressed = TraceCompressor.compress_trace(trace, min_iterations=2)
    
    assert len(compressed) == 1
    assert isinstance(compressed[0], LoopBlock)
    assert compressed[0].iterations == 2
    
    outer_body = compressed[0].body
    assert len(outer_body) == 3
    assert outer_body[0].address == 0x1000
    
    inner_block = outer_body[1]
    assert isinstance(inner_block, LoopBlock)
    assert inner_block.iterations == 3
    assert len(inner_block.body) == 2
    assert inner_block.body[0].address == 0x2000
    assert inner_block.body[1].address == 0x2004
    
    assert outer_body[2].address == 0x1004

def test_vsa_evaluator_nested_loops():
    from asm_analyzer.engine.vsa_evaluator import LoopEvaluator
    trace = [
        create_mock_record(1, 0x1000, "add", "eax, 1"),
        LoopBlock(body=[create_mock_record(2, 0x2000, "add", "ebx, 5")], iterations=10)
    ]
    outer_block = LoopBlock(body=trace, iterations=2)
    
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(outer_block)
    
    assert summary.deltas["eax"] == 1
    assert summary.deltas["ebx"] == 50

def test_symbolic_nested_loops_z3_composition():
    """
    Test that Z3 can solve for both N_outer and N_inner simultaneously,
    where N_inner drives an inner polycyclic pattern [86, 85] and N_outer repeats it!
    """
    import z3
    from asm_analyzer.engine.vsa_evaluator import LoopSummary
    from asm_analyzer.engine.translator import Z3Translator
    
    # 1. Build Inner Loop Summary (Polycyclic pattern [86, 85])
    inner_sum = LoopSummary()
    inner_sum.tick = 20
    inner_sum.patterns["rax"] = [86, 85] # P=2, Sum=171
    inner_sum.deltas["rdx"] = 1 # inner counter
    
    # 2. Build Outer Loop Summary
    outer_sum = LoopSummary()
    outer_sum.tick = 10
    outer_sum.inner_summaries = [inner_sum]
    outer_sum.direct_deltas["rcx"] = 1 # outer counter
    outer_sum.deltas["rcx"] = 1
    outer_sum.deltas["rax"] = 171
    
    translator = Z3Translator()
    translator.translate_loop_summary(outer_sum, max_iterations=1000)
    
    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
        
    N_outer = z3.BitVec('LoopCounter_t10', 64)
    N_inner = z3.BitVec('LoopCounter_t20', 64)
    rax_final = translator.reg_state['rax']
    rax_init = z3.BitVec('rax_t0', 64)
    
    # Target: Initial rax = 0. We run outer loop 10 times.
    # We want rax_final to reach 2570.
    # For N_inner = 3: inner_delta = 86 + 85 + 86 = 257.
    # Total rax = 10 * 257 = 2570!
    solver.add(rax_init == 0)
    solver.add(N_outer == 10)
    solver.add(rax_final == 2570)
    
    assert solver.check() == z3.sat
    m = solver.model()
    solved_n_inner = m.eval(N_inner).as_long()
    assert solved_n_inner == 3
    print(f"\n[SUCCESS] Z3 solved N_inner = {solved_n_inner} (expected 3) for target 2570!")
