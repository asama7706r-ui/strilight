#!/usr/bin/env python3
"""
Example 01: Python Algebraic Loop Acceleration (@accelerate)
============================================================
Demonstrates how Strilight accelerates Python iterative loops into exact O(1)
closed-form recurrence kernels with reflection contracts.
"""

import sys
import os
import time

# Ensure repository root is in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import strilight as sl


STEP_INC = 7


# Standard iterative implementation (O(N))
def unaccelerated_simulation(N: int) -> int:
    total = 0
    for _ in range(N):
        total += STEP_INC
    return total


# Strilight accelerated implementation (O(1) closed-form)
@sl.accelerate
def accelerated_simulation(N: int) -> int:
    total = 0
    for _ in range(N):
        total += STEP_INC
    return total


def main():
    print("=" * 70)
    print("  [Strilight] Example 01: Python Algebraic Recurrence Acceleration")
    print("=" * 70)

    N = 100_000_000
    print(f"\nConfiguration: N = {N:,} iterations, STEP_INC = {STEP_INC}\n")

    # Warmup / JIT compilation pass
    _ = accelerated_simulation(1)

    # 1. Benchmark Accelerated Execution (O(1))
    t0 = time.perf_counter()
    fast_result = accelerated_simulation(N)
    t_fast = time.perf_counter() - t0
    print(f"[-] Accelerated Execution Result : {fast_result}")
    print(f"[-] Accelerated Execution Time   : {t_fast * 1e6:.2f} microseconds (O(1))")

    # 2. Benchmark Standard Execution on smaller scale (for comparison)
    n_sample = 1_000_000
    t0 = time.perf_counter()
    sample_result = unaccelerated_simulation(n_sample)
    t_slow = time.perf_counter() - t0
    print(f"\n[-] Baseline Iterative Time ({n_sample:,} iters): {t_slow * 1e3:.2f} ms (O(N))")

    # 3. Inspect Mathematical Reflection Contract
    if hasattr(accelerated_simulation, "_invariant_contract"):
        contract = accelerated_simulation._invariant_contract
        print(f"\n[-] Mathematical Reflection Contract Attached:")
        print(f"    * Contract Type : {type(contract).__name__}")
        if hasattr(contract, "to_dict"):
            print(f"    * Contract Data : {contract.to_dict()}")


if __name__ == "__main__":
    main()
