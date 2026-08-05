import pytest
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant, Ancestor, BackwardSliceTracker

def test_trace_record():
    r = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 1", size=5)
    r.regs_write = ["rax"]
    assert str(r) == "<TraceRecord Tick:0001 mov rax, 1>"

def test_descendant_ancestor():
    d = Descendant("rax", 5)
    assert d.target == "rax"
    assert d.at_tick == 5
    
    r = TraceRecord(tick=2, address=0x1000, mnemonic="mov", op_str="rbx, 1", size=5)
    a = Ancestor("rbx", 2, r)
    assert a.target == "rbx"
    assert a.modified_at_tick == 2
    assert a.instruction == r

def test_tracker_add_record():
    tracker = Tracker()
    r = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 1", size=5)
    tracker.add_trace(r)
    
    assert len(tracker.trace_history) == 1
    assert tracker.trace_history[0] == r

def test_backward_slice():
    tracker = Tracker()
    
    # tick 1: mov rbx, 5
    r1 = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rbx, 5", size=5)
    r1.regs_write = ["rbx"]
    
    # tick 2: add rax, rbx
    r2 = TraceRecord(tick=2, address=0x1005, mnemonic="add", op_str="rax, rbx", size=3)
    r2.regs_read = ["rax", "rbx"]
    r2.regs_write = ["rax"]
    
    tracker.add_trace(r1)
    tracker.add_trace(r2)
    
    desc = Descendant("rax", 2)
    slice_records = tracker.build_backward_slice(desc)
    
    # Since r2 modifies rax and reads rbx, we need r2 and r1
    assert len(slice_records) == 2
    assert slice_records[0].tick == 2
    assert slice_records[1].tick == 1

