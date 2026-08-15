import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.loop_compressor import TraceCompressor, LoopBlock

def create_trace(addresses):
    return [TraceRecord(tick=i+1, address=addr, size=4, mnemonic="mock", op_str="mock") for i, addr in enumerate(addresses)]

def test_no_loop():
    trace = create_trace([0x10, 0x20, 0x30, 0x40])
    compressed = TraceCompressor.compress_trace(trace)
    assert len(compressed) == 4
    assert not any(isinstance(x, LoopBlock) for x in compressed)

def test_simple_loop():
    # A B C repeats 4 times
    trace = create_trace([0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30])
    compressed = TraceCompressor.compress_trace(trace, min_iterations=3)
    
    assert len(compressed) == 1
    assert isinstance(compressed[0], LoopBlock)
    assert compressed[0].iterations == 4
    assert len(compressed[0].body) == 3
    assert [r.address for r in compressed[0].body] == [0x10, 0x20, 0x30]

def test_loop_with_prefix_suffix():
    # Prefix
    trace = create_trace([0x05])
    # Loop (A B repeats 3 times)
    trace.extend(create_trace([0x10, 0x20, 0x10, 0x20, 0x10, 0x20]))
    # Suffix
    trace.extend(create_trace([0x99]))
    
    compressed = TraceCompressor.compress_trace(trace, min_iterations=3)
    
    assert len(compressed) == 3
    assert not isinstance(compressed[0], LoopBlock)
    assert compressed[0].address == 0x05
    
    assert isinstance(compressed[1], LoopBlock)
    assert compressed[1].iterations == 3
    assert len(compressed[1].body) == 2
    
    assert not isinstance(compressed[2], LoopBlock)
    assert compressed[2].address == 0x99

def test_complex_unrolled_loop():
    # What if the loop pattern has variations and we find a macro-block?
    # Pattern [A, B, C, A, B, D] repeating 3 times.
    pattern = [0x10, 0x20, 0x30, 0x10, 0x20, 0x40]
    trace = create_trace(pattern * 3)
    
    compressed = TraceCompressor.compress_trace(trace, min_iterations=3)
    
    assert len(compressed) == 1
    assert isinstance(compressed[0], LoopBlock)
    assert compressed[0].iterations == 3
    assert len(compressed[0].body) == 6
    assert [r.address for r in compressed[0].body] == pattern

if __name__ == "__main__":
    pytest.main(["-v", __file__])
