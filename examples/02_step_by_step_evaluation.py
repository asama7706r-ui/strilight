"""
Example 02: Step-by-Step Disassembly, Compression & VSA Evaluation
Demonstrates inspecting instructions, hierarchical LoopBlock structures, and affine step extraction.
"""

import os
import sys

# Auto-inject project root into sys.path for standalone execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import strilight as sl


def main():
    print("=" * 60)
    print("  [Strilight] Example 02: Step-by-Step VSA Evaluation")
    print("=" * 60)

    # 1. Bytecode for a multi-variable loop:
    loop_bytes = bytes.fromhex("83c008" "83eb03" "6bd202" "ffc1" "81f9a0860100" "7ced")

    # 2. Step 1: Disassemble with Capstone
    print("\n[Step 1] Disassembling raw bytes:")
    instructions = sl.disassemble(loop_bytes, base_address=0x1000, bit_mode=64)
    for insn in instructions:
        print(f"  0x{insn.address:04x}: {insn.mnemonic:<6} {insn.op_str}")

    # 3. Step 2: Package into a symbolic LoopBlock
    print("\n[Step 2] Packaging into hierarchical LoopBlock:")
    block = sl.LoopBlock(body=instructions, iterations=50000)
    print(f"  LoopBlock Iterations : {block.iterations:,}")
    print(f"  LoopBlock Body Size  : {len(block.body)} instructions")

    # 4. Step 3: Pure Data-flow Evaluation via LoopEvaluator
    print("\n[Step 3] Evaluating loop invariants via sl.evaluate:")
    summary = sl.evaluate(block)

    print(f"  * Scalar Deltas    : {summary.deltas}")
    print(f"  * Direct Deltas    : {summary.direct_deltas}")
    print(f"  * Exit Condition   : {summary.exit_condition}")


if __name__ == "__main__":
    main()
