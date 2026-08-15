import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import LoopBlock
from asm_analyzer.engine.vsa_evaluator import LoopEvaluator

def create_mock_record(tick, addr, mnemonic, op_str):
    return TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)

def test_vsa_evaluator_harsh_loop():
    # 1. Create a mock loop body representing a complex loop
    body = [
        create_mock_record(1, 0x1000, "add", "eax, 4"),    # Stride +4
        create_mock_record(2, 0x1004, "sub", "ebx, 2"),    # Stride -2
        create_mock_record(3, 0x1008, "mov", "edx, 5"),    # Constant 5
        create_mock_record(4, 0x100C, "inc", "ecx"),       # Stride +1
        create_mock_record(5, 0x1010, "cmp", "ecx, 1000"), # Exit Condition 1
        create_mock_record(6, 0x1014, "jle", "0x1000")     # Exit Condition 2
    ]
    
    # 2. Package it into a LoopBlock representing 1000 dynamic iterations
    loop_block = LoopBlock(body=body, iterations=1000)
    
    # 3. Initialize our Driver (LoopEvaluator)
    evaluator = LoopEvaluator()
    
    # 4. Evaluate the loop
    summary = evaluator.evaluate(loop_block)
    
    # 5. Assert the Harsh Extractions!
    assert summary is not None
    
    # Assert Deltas (Strides)
    assert "eax" in summary.deltas
    assert summary.deltas["eax"] == 4
    
    assert "ebx" in summary.deltas
    assert summary.deltas["ebx"] == -2
    
    assert "ecx" in summary.deltas
    assert summary.deltas["ecx"] == 1
    
    # Assert Constant Sets
    assert "edx" in summary.constant_sets
    assert summary.constant_sets["edx"] == 5
    
    # Assert Exit Condition Capture
    assert summary.exit_condition == "cmp ecx, 1000 -> jle"

if __name__ == "__main__":
    pytest.main(["-v", __file__])
