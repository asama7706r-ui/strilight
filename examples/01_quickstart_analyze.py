"""
Example 01: Quickstart Loop Analysis
Demonstrates one-line extraction of loop transformations and invariant contracts.
"""

import os
import sys

# Auto-inject project root into sys.path for standalone execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import strilight as sl


def main():
    print("=" * 60)
    print("  [Strilight] Example 01: One-Line Loop Analysis")
    print("=" * 60)

    # 1. Raw x86-64 machine code loop:
    # 0x1000: add eax, 8
    # 0x1003: sub ebx, 3
    # 0x1006: imul edx, edx, 2
    # 0x1009: inc ecx
    # 0x100b: cmp ecx, 100000
    # 0x1011: jl 0x1000
    loop_hex = "83c008" "83eb03" "6bd202" "ffc1" "81f9a0860100" "7ced"
    code_bytes = bytes.fromhex(loop_hex)

    # 2. Perform one-line analysis:
    summary = sl.analyze(code_bytes, iterations=100000)

    print(f"\n[+] Analysis Complete!")
    print(f"[-] Extracted Register Deltas:")
    for reg, delta in summary.deltas.items():
        print(f"    * {reg.upper():<4} : {delta:+d} per iteration")

    print(f"\n[-] Extracted Loop Exit Predicate: {summary.exit_condition}")

    # 3. View the formal mathematical invariant contract:
    contract = summary.invariant_contract
    if contract:
        print(f"\n[-] Formal Invariant Contract:")
        print(f"    * Boundary Rule: {contract.get_exit_invariant_rule()}")


if __name__ == "__main__":
    main()
