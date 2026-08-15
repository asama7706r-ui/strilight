import sys
import os
import z3
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import LoopBlock
from asm_analyzer.engine.vsa_evaluator import LoopEvaluator
from asm_analyzer.engine.translator import Z3Translator

def create_mock_record(tick, addr, mnemonic, op_str):
    return TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)

def test_full_engine_integration_with_optimizer():
    # 1. We create a loop that adds 4 to EAX every iteration
    body = [
        create_mock_record(1, 0x1000, "add", "eax, 4"),
        create_mock_record(2, 0x1004, "mov", "ebx, 10"), # Constant
    ]
    loop_block = LoopBlock(body=body, iterations=1000)
    
    # 2. Phase 2: Loop Evaluator
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(loop_block)
    
    # Verify Phase 2 worked
    assert summary.deltas["eax"] == 4
    assert summary.constant_sets["ebx"] == 10
    
    # 3. Phase 3: Z3 Translator
    translator = Z3Translator()
    
    # In a real scenario, the Tracker would have initialized EAX to some symbolic value.
    # Let's say EAX starts as a symbolic variable.
    eax_init = translator._get_phys_reg("eax")
    
    # Now we pass the summary to the translator!
    translator.translate_loop_summary(summary, max_iterations=1000)
    
    # 4. The Goal (Assertion):
    # We want the FINAL value of EAX to be exactly 5000.
    eax_final = translator._get_phys_reg("eax")
    translator.solver.add(eax_final == 5000)
    
    # 5. Let Z3 solve it!
    # Because we used z3.Optimize() and minimize(N), we expect it to find the shortest N.
    # If eax_init == 1000, N = 1000.
    # To make it interesting, let's constrain eax_init >= 0
    translator.solver.add(z3.UGE(eax_init, 0))
    
    result = translator.solver.check()
    assert result == z3.sat, "Z3 failed to solve the integrated equation!"
    
    model = translator.solver.model()
    
    # Evaluate N
    # N is the LoopCounter we created inside translate_loop_summary.
    # We can fetch it from the model by finding the declaration.
    n_val = None
    for d in model.decls():
        if d.name() == 'LoopCounter':
            n_val = model[d].as_long()
            break
            
    assert n_val is not None, "LoopCounter variable not found in model"
    
    # Since we asked to minimize N, N should be 0, and EAX_init should be 5000.
    # Why? Because if N=0, EAX_final = EAX_init + 0 = 5000 -> EAX_init = 5000.
    # Let's check!
    eax_init_val = model.eval(eax_init).as_long()
    
    assert n_val == 0
    assert eax_init_val == 5000
    
    # What if we constrain eax_init == 1000? Then N MUST be 1000!
    # z3.Optimize can be buggy with push/pop after check(), so we create a fresh translator
    translator2 = Z3Translator()
    eax_init2 = translator2._get_phys_reg("eax")
    translator2.translate_loop_summary(summary, max_iterations=1000)
    eax_final2 = translator2._get_phys_reg("eax")
    
    translator2.solver.add(eax_final2 == 5000)
    translator2.solver.add(eax_init2 == 1000)
    
    result2 = translator2.solver.check()
    if result2 != z3.sat:
        print("Assertions:")
        for a in translator2.solver.assertions():
          result2 = translator2.solver.check()
    assert result2 == z3.sat
    
    print("\n--- Z3 SOLVER STATE ---")
    print("Assertions:")
    for a in translator2.solver.assertions():
        print(f"  {a}")
        
    model2 = translator2.solver.model()
    print("\nModel Solution:")
    for d in model2.decls():
        print(f"  {d.name()} = {model2[d]}")
    print("-----------------------\n")
    
    n_val2 = None
    for d in model2.decls():
        if d.name() == 'LoopCounter':
            n_val2 = model2[d].as_long()
            break
            
    assert n_val2 == 1000 # (5000 - 1000) / 4 = 1000

if __name__ == "__main__":
    pytest.main(["-v", __file__])
