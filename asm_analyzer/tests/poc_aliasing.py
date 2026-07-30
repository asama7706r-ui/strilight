from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant

def main():
    tracker = Tracker()
    
    # 1. mov ebx, 0x1000
    t1 = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="ebx, 0x1000")
    t1.regs_read = []
    t1.regs_write = ["ebx"]
    tracker.add_trace(t1)
    
    # 2. mov [ebx], eax  (May-Alias! ebx happens to be 0x1000, but it's a symbolic pointer)
    t2 = TraceRecord(tick=2, address=0x1002, mnemonic="mov", op_str="dword ptr [ebx], eax")
    t2.regs_read = ["ebx", "eax"]
    t2.regs_write = []
    t2.mem_read = []
    t2.mem_write = [0x1000]
    tracker.add_trace(t2)
    
    # 3. mov ecx, [0x1000] (Target: 0x1000)
    t3 = TraceRecord(tick=3, address=0x1004, mnemonic="mov", op_str="ecx, dword ptr [0x1000]")
    t3.regs_read = []
    t3.regs_write = ["ecx"]
    t3.mem_read = [0x1000]
    t3.mem_write = []
    tracker.add_trace(t3)
    
    print("\n[+] Starting Memory Aliasing Test")
    
    # Start tracking memory 0x1000 from Tick 3
    initial_desc = Descendant(target=0x1000, at_tick=3, is_memory=True)
    
    slice_records = tracker.build_backward_slice(initial_desc)
    
    print("\n[+] Final Chronologically Merged Slice:")
    for instr in slice_records:
        print(f"    {instr} (Requested Flags: {instr.requested_flags})")
        
    print("\n[+] Path-Tree Cache Content:")
    for key, cached_slice in tracker.path_tree.memoized_slices.items():
        print(f"    Cache Key {key} -> Cached Slice Length: {len(cached_slice)}")

if __name__ == "__main__":
    main()
