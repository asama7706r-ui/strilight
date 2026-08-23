import sys
import os
import pytest
import z3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from strilight.engine.tracker import Tracker, TraceRecord, Descendant
from strilight.engine.translator import Z3Translator
from strilight.engine.loop_compressor import TraceCompressor

def create_mock_record(tick, addr, mnemonic, op_str, regs_read=None, regs_write=None):
    r = TraceRecord(tick=tick, address=addr, size=4, mnemonic=mnemonic, op_str=op_str)
    r.regs_read = regs_read or []
    r.regs_write = regs_write or []
    
    # Mock operands based on op_str (e.g. "eax, 4" -> [{'type':'reg','value':'eax','size':32}, {'type':'imm','value':4,'size':32}])
    operands = []
    if op_str:
        for part in op_str.split(','):
            part = part.strip()
            if part.isdigit() or part.startswith("0x") or part.startswith("-"):
                val = int(part, 16) if part.startswith("0x") else int(part)
                operands.append({'type': 'imm', 'value': val, 'size': 4})
            else:
                operands.append({'type': 'reg', 'value': part, 'size': 4})
    r.operands = operands
    return r

def test_loop_taint_tracking():
    tracker = Tracker()
    
    # Tick 1: Initialize the Target (EAX) and the Tainted Input (EDX)
    tracker.add_trace(create_mock_record(1, 0x1000, "mov", "eax, 0", regs_write=["eax"]))
    tracker.add_trace(create_mock_record(2, 0x1004, "mov", "edx, 100", regs_write=["edx"])) # The tainted input
    
    # Tick 3: Initialize loop counter ECX
    tracker.add_trace(create_mock_record(3, 0x1008, "mov", "ecx, 0", regs_write=["ecx"]))
    
    # Ticks 4-23: A loop that runs 10 times. EAX += 4. ECX is the counter. Exit when ECX == EDX.
    tick = 4
    for _ in range(10):
        # Body
        tracker.add_trace(create_mock_record(tick, 0x2000, "add", "eax, 4", regs_read=["eax"], regs_write=["eax"]))
        tick += 1
        tracker.add_trace(create_mock_record(tick, 0x2004, "inc", "ecx", regs_read=["ecx"], regs_write=["ecx"]))
        tick += 1
        # Exit Condition
        tracker.add_trace(create_mock_record(tick, 0x2008, "cmp", "ecx, edx", regs_read=["ecx", "edx"]))
        tick += 1
        tracker.add_trace(create_mock_record(tick, 0x200c, "jne", "0x2000", regs_read=["eflags"]))
        tick += 1
        
    # Tick 44: Read EAX (Trigger backward slice)
    tracker.add_trace(create_mock_record(tick, 0x3000, "mov", "ebx, eax", regs_read=["eax"], regs_write=["ebx"]))
    
    # 1. Compress the trace to create LoopBlocks
    tracker.compress_trace()
    
    # 2. Build Backward Slice tracking EAX starting from Tick 44
    slice_records = tracker.build_backward_slice(Descendant("eax", tick))
    
    # The slice should contain LoopSummary instead of LoopBlock, and should track EDX because of the exit condition
    assert len(slice_records) > 0
    
    # 3. Translate to Z3
    translator = Z3Translator()
    translator.translate_slice(slice_records)
    
    # 4. Check Z3 output
    # The logic is: N is the loop counter.
    # ecx_t1 = ecx_t0 + 1 * N
    # ecx_t0 = 0
    # cmp ecx, edx means ecx_t1 == edx_t0 -> 0 + N == 100 -> N = 100
    # eax_t1 = eax_t0 + 4 * N
    # eax_t0 = 0 -> eax_t1 = 400
    # Since translator.solver.check() uses optimize, we can ask for the value of EAX at the end
    
    eax_final = translator._get_phys_reg("rax")
    
    if translator.solver.check() == z3.sat:
        model = translator.solver.model()
        result = model.eval(eax_final, model_completion=True)
        print(f"Z3 Evaluated EAX Final: {result}")
        assert result.as_long() == 400
    else:
        pytest.fail("Z3 returned UNSAT")
