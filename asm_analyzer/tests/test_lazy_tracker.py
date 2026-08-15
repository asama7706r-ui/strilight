import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant

def create_mock_record(tick, addr, mnemonic, op_str, regs_read=None, regs_write=None, mem_read=None, mem_write=None):
    r = TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)
    r.regs_read = regs_read or []
    r.regs_write = regs_write or []
    r.mem_read = mem_read or []
    r.mem_write = mem_write or []
    r.operands = []
    return r

def test_lazy_skip_backward():
    tracker = Tracker()
    
    # Tick 1: Initialize RAX (This is our target to find)
    tracker.add_trace(create_mock_record(1, 0x1000, "mov", "rax, 1", regs_write=["rax"]))
    
    # Ticks 2-31: A noisy loop that only modifies RBX and RCX, running 15 times
    tick = 2
    for _ in range(15):
        tracker.add_trace(create_mock_record(tick, 0x2000, "inc", "rbx", regs_read=["rbx"], regs_write=["rbx"]))
        tick += 1
        tracker.add_trace(create_mock_record(tick, 0x2004, "dec", "rcx", regs_read=["rcx"], regs_write=["rcx"]))
        tick += 1
        
    # Tick 32: Instruction that reads RAX (We start backward slicing from here)
    tracker.add_trace(create_mock_record(tick, 0x3000, "mov", "rdx, rax", regs_read=["rax"], regs_write=["rdx"]))
    
    # Phase 1: Compress the trace
    tracker.compress_trace()
    
    # The compressed trace should be exactly 3 elements: [Tick 1, LoopBlock, Tick 32]
    assert len(tracker.compressed_trace) == 3
    
    # Phase 2 (Deferred): Track RDX backwards starting from Tick 32. 
    # Tick 32 writes to RDX from RAX, so it will be added to the slice and trigger a search for RAX.
    descendant = Descendant(target="rdx", at_tick=32)
    slice_records = tracker.build_backward_slice(descendant)
    
    # The slice should ONLY contain Tick 32 and Tick 1. 
    # The 30 instructions in the loop should have been LAZILY SKIPPED!
    assert len(slice_records) == 2
    assert slice_records[0].tick == 32
    assert slice_records[1].tick == 1

def test_phase2_trigger():
    tracker = Tracker()
    
    tracker.add_trace(create_mock_record(1, 0x1000, "mov", "rbx, 0", regs_write=["rbx"]))
    
    tick = 2
    for _ in range(15):
        tracker.add_trace(create_mock_record(tick, 0x2000, "inc", "rbx", regs_read=["rbx"], regs_write=["rbx"]))
        tick += 1
        
    tracker.add_trace(create_mock_record(tick, 0x3000, "mov", "rdx, rbx", regs_read=["rbx"], regs_write=["rdx"]))
    
    tracker.compress_trace()
    
    # Track RBX backwards. Since the loop modifies RBX, it should trigger Phase 2.
    descendant = Descendant(target="rbx", at_tick=tick)
    
    with pytest.raises(NotImplementedError, match="Phase 2 Required"):
        tracker.build_backward_slice(descendant)

if __name__ == "__main__":
    pytest.main(["-v", "-s", __file__])
