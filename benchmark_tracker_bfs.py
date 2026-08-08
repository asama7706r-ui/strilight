import time
from collections import deque
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant

def benchmark_bfs():
    # Setup tracker
    tracker = Tracker()
    
    # We can just simulate the worklist logic itself directly to prove the O(N) vs O(1) impact,
    # or we can construct a Tracker trace that triggers many descendants.
    
    # Let's just create a test that adds a lot of dependencies.
    N = 2000
    
    # A chain of JMPs that depend on flags.
    for i in range(1, N + 1):
        r = TraceRecord(tick=i, address=0x1000+i, mnemonic="jae", op_str="0x2000", size=2)
        r.operands = [{'type': 'imm', 'value': 0x2000, 'size': 8}]
        tracker.add_trace(r)
        
    start_time = time.perf_counter()
    desc = Descendant("rax", N)
    # Actually wait, hunting_for_control_dependency needs to be True.
    # It's True only if it hits a taint breaker and the mnemonic is not call.
    # Taint breaker is len(regs_read) == 0 and len(mem_read) == 0.
    # So `jae` is a taint breaker. It sets hunting_for_control_dependency = True. Wait no, is_taint_breaker logic sets it to False?
    # Ah:
    # if is_taint_breaker and record.mnemonic != 'call':
    #     hunting_for_control_dependency = False # Wait! If it's a taint breaker, it DISABLES control dependency?
    # Wait, the code says:
    # if is_taint_breaker and record.mnemonic != 'call':
    #     print(...)
    # if is_taint_breaker:
    #     hunting_for_control_dependency = False
        
    pass

import timeit

def pure_list_benchmark():
    code = """
worklist = list(range(100000))
while worklist:
    worklist.pop(0)
"""
    return timeit.timeit(code, number=1)

def pure_deque_benchmark():
    code = """
from collections import deque
worklist = deque(range(100000))
while worklist:
    worklist.popleft()
"""
    return timeit.timeit(code, number=1)

if __name__ == "__main__":
    print(f"List pop(0): {pure_list_benchmark():.4f}s")
    print(f"Deque popleft: {pure_deque_benchmark():.4f}s")
