import time
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant

def benchmark_tracker():
    tracker = Tracker()
    # Let's trigger "may_alias_triggered = True" repeatedly.
    # It adds a new Descendant for each pointer reg used.
    # We can create a sequence of instructions doing absolute writes with pointer regs read.
    # Wait, if `tracked_mem and record.mem_write` and `pointer_regs_used`:
    # pointer_regs_used = [r for r in record.regs_read if r in ('eax', 'ebx', ...)]
    
    # We want a target memory to track.
    desc = Descendant(0x1000, at_tick=5000)
    
    # Fill trace
    for i in range(1, 5001):
        r = TraceRecord(tick=i, address=0x100+i, mnemonic="mov", op_str="[eax], ebx", size=2)
        r.mem_write = [0x1000] # It writes to memory. Wait, if it writes to memory, and uses eax, it triggers May-Alias.
        r.regs_read = ["eax"]  # pointer reg
        tracker.add_trace(r)
        
    start_time = time.perf_counter()
    tracker.build_backward_slice(desc)
    end_time = time.perf_counter()
    
    print(f"Time taken: {end_time - start_time:.4f}s")

if __name__ == "__main__":
    benchmark_tracker()
