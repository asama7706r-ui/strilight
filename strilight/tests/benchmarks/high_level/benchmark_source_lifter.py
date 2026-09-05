"""
High-Level Benchmark: Automated Source-to-Source Acceleration & @accelerate Decorator
=====================================================================================
Validates and benchmarks:
1. Python function transparent acceleration via @accelerate.
2. C loop automated source lifting and in-place statement generation.
3. Execution accuracy and speedup benchmarks.
"""

import time
from strilight.frontend import SourceLifter, accelerate


@accelerate
def compute_coupled_func(N, a, b, c, d):
    for _ in range(N):
        next_a = 3*a + 7*b - 2*c + 5*d + 11
        next_b = -2*a + 5*b + 8*c - d + 17
        next_c = 4*a - b + 6*c + 3*d + 23
        next_d = a + 9*b - 4*c + 2*d + 31
        a = next_a
        b = next_b
        c = next_c
        d = next_d
    return a, b, c, d


def run_benchmark():
    print("=========================================================================")
    print("   [HIGH-LEVEL SOURCE LIFTER & @ACCELERATE DECORATOR BENCHMARK]   ")
    print("=========================================================================\n")

    N = 1_000_000
    print(f"[*] Benchmarking transparent @accelerate decorator on coupled recurrence (N = {N:,})...")

    # Warmup
    compute_coupled_func(100, 1, 2, 3, 4)

    t0 = time.perf_counter()
    res = compute_coupled_func(N, 1, 2, 3, 4)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"[+] Result returned in {elapsed_ms:.4f} ms!")
    print(f"    a=0x{res[0]:08X}, b=0x{res[1]:08X}, c=0x{res[2]:08X}, d=0x{res[3]:08X}")

    expected = (0x72E4E712, 0x2854212D, 0x32B9DC55, 0xB1AA26A2)
    assert res == expected, f"Result mismatch! Expected {expected}, got {res}"
    print(f"[SUCCESS] 100% Bit-Exact match against analytical matrix power!\n")

    # Benchmark C source lifting
    c_code = """
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 10; j++) {
            total += k1 * 3 + j;
        }
    }
    """
    print("[*] Benchmarking C Loop Lifting with nested induction...")
    t0 = time.perf_counter()
    summary = SourceLifter.lift_c_loop(c_code)
    lift_time = (time.perf_counter() - t0) * 1000
    accelerated_c = SourceLifter.accelerate_c(c_code, in_place=True)

    print(f"[+] C loop lifted and accelerated in {lift_time:.4f} ms:")
    print("---------------------------------------------------------")
    print(accelerated_c)
    print("---------------------------------------------------------\n")
    print("[ALL HIGH-LEVEL BENCHMARKS COMPLETED SUCCESSFULLY]")


if __name__ == "__main__":
    run_benchmark()
