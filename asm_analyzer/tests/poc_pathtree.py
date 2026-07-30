from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant

def main():
    tracker = Tracker()
    
    # 1. mov ebx, 10
    t1 = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="ebx, 10")
    t1.regs_read = []
    t1.regs_write = ["ebx"]
    tracker.add_trace(t1)
    
    # 2. cmp ebx, 10
    t2 = TraceRecord(tick=2, address=0x1002, mnemonic="cmp", op_str="ebx, 10")
    t2.regs_read = ["ebx"]
    t2.regs_write = ["eflags"]
    tracker.add_trace(t2)
    
    # 3. je target
    t3 = TraceRecord(tick=3, address=0x1004, mnemonic="je", op_str="target")
    t3.regs_read = ["eflags"]
    t3.regs_write = []
    tracker.add_trace(t3)
    
    # 4. add eax, 5
    t4 = TraceRecord(tick=4, address=0x1006, mnemonic="add", op_str="eax, 5")
    t4.regs_read = ["eax"]
    t4.regs_write = ["eax", "eflags"]
    tracker.add_trace(t4)
    
    print("\n[+] Starting Nested Sub-Slice Test via Worklist")
    
    # Start tracking EAX from Tick 4
    initial_desc = Descendant(target="eax", at_tick=4)
    
    # To simulate hitting a control dependency (since normally the tracker detects taint breakers to start hunting for control flow),
    # we will artificially set hunting_for_control_dependency = True if we hit Tick 4 for this test,
    # OR we can just add a Taint Breaker at Tick 4 so it naturally starts hunting!
    
    # Let's make t4 a taint breaker by saying it reads nothing (like mov eax, 5)
    t4.mnemonic = "mov"
    t4.op_str = "eax, 5"
    t4.regs_read = []
    
    slice_records = tracker.build_backward_slice(initial_desc)
    
    print("\n[+] Final Chronologically Merged Slice:")
    for instr in slice_records:
        print(f"    {instr} (Requested Flags: {instr.requested_flags})")
        
    print("\n[+] Path-Tree Cache Content:")
    for key, cached_slice in tracker.path_tree.memoized_slices.items():
        print(f"    Cache Key {key} -> Cached Slice Length: {len(cached_slice)}")

if __name__ == "__main__":
    main()
