"""
=============================================================================
             STRIDED LOOP COMPRESSOR & SMT LIFTING ENGINE DEMO
=============================================================================
Showcases:
1. Raw Machine Code Bytes Disassembly via Capstone -> Instruction Schema
2. Trace Compression from 100,000 instructions -> LoopBlock in <1 ms
3. Strided Interval & Dual-Mask VSA Evaluation
4. Instant Zero-Unroll SMT Lifting to Z3 (Solving in O(1) time)
=============================================================================
"""

import sys
import time
import capstone
import z3

from strilight import (
    Instruction,
    LoopBlock,
    TraceCompressor,
    LoopEvaluator,
    StridedInterval
)
from strilight.engine.translator import Z3Translator


def main():
    print("=" * 70)
    print("   [+] STRIDED LOOP COMPRESSOR & ZERO-UNROLL SMT LIFTING DEMO")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # 1. Raw x86-64 Machine Code Loop (Hex Bytes)
    # -------------------------------------------------------------------------
    # Loop body:
    # 0x1000: add eax, 8           (83 c0 08)  -> Stride +8 per iteration
    # 0x1003: sub ebx, 3           (83 eb 03)  -> Stride -3 per iteration
    # 0x1006: imul edx, edx, 2     (6b d2 02)  -> Multiplicative Stride
    # 0x1009: inc ecx              (ff c1)     -> Loop counter +1
    # 0x100b: cmp ecx, 100000      (81 f9 a0 86 01 00) -> Exit Condition (100,000 iters)
    # 0x1011: jl 0x1000            (7c ed)     -> Back-edge jump to 0x1000
    loop_hex = "83c008" "83eb03" "6bd202" "ffc1" "81f9a0860100" "7ced"
    code_bytes = bytes.fromhex(loop_hex)

    print(f"\n[Step 1] Disassembling raw machine code bytes ({len(code_bytes)} bytes) via Capstone...")
    instructions = Instruction.disassemble_bytes(code_bytes, base_address=0x1000, bit_mode=64)
    for insn in instructions:
        print(f"  0x{insn.address:04x}: {insn.mnemonic:<6} {insn.op_str}")

    # -------------------------------------------------------------------------
    # 2. Trace Compression
    # -------------------------------------------------------------------------
    iterations = 100000
    print(f"\n[Step 2] Simulating Execution Trace with N = {iterations:,} iterations...")
    
    # We package the loop body into a LoopBlock representing 100,000 dynamic loop passes
    loop_block = LoopBlock(body=instructions, iterations=iterations)
    print(f"  -> Compressed into: {loop_block}")

    # -------------------------------------------------------------------------
    # 3. Mathematical Evaluation via VSA & Strided Interval Domain
    # -------------------------------------------------------------------------
    print("\n[Step 3] Evaluating Abstract State & Loop Invariants (Strided Interval Domain)...")
    start_vsa = time.perf_counter()
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(loop_block)
    vsa_time_ms = (time.perf_counter() - start_vsa) * 1000

    print(f"  [-] VSA Evaluation Time: {vsa_time_ms:.3f} ms")
    print(f"  [-] Extracted Register Deltas:")
    for reg, delta in summary.deltas.items():
        print(f"     - {reg.upper():<4} : Delta = {delta:+d} per iteration")
    print(f"  [-] Extracted Exit Condition: {summary.exit_condition}")

    # -------------------------------------------------------------------------
    # 4. Zero-Unroll SMT Lifting to Z3
    # -------------------------------------------------------------------------
    print(f"\n[Step 4] Lifting to Z3 SMT Solver with Zero-Unroll O(1) Closed-Form Encoding...")
    start_z3 = time.perf_counter()
    translator = Z3Translator()

    # Initial state: EAX = 0, EBX = 500,000, ECX = 0
    translator.solver.add(translator.get_register('eax') == 0)
    translator.solver.add(translator.get_register('ebx') == 500000)
    translator.solver.add(translator.get_register('ecx') == 0)

    # Translate the loop summary into closed-form Z3 constraints in O(1)
    translator.translate_loop_summary(summary, max_iterations=iterations)

    # Solve for target condition: when does EAX reach 800,000?
    target_eax = 800000
    translator.solver.add(translator.get_register('eax') == target_eax)

    # Solve with Z3
    check_res = translator.solver.check()
    z3_time_ms = (time.perf_counter() - start_z3) * 1000

    print(f"  [-] Z3 SMT Solving Time: {z3_time_ms:.3f} ms")
    print(f"  [-] Solver Result: {check_res}")

    if check_res == z3.sat:
        model = translator.solver.model()
        solved_N = model.eval(summary.loop_counter_var).as_long()
        solved_eax = model.eval(translator.get_register('eax')).as_long()
        solved_ebx = model.eval(translator.get_register('ebx')).as_long()
        
        print("\n" + "=" * 70)
        print(f"   [SUCCESS] MATHEMATICAL SOLUTION FOUND IN {z3_time_ms + vsa_time_ms:.3f} ms TOTAL!")
        print("=" * 70)
        print(f"   * Solved Iteration Count (N) : {solved_N:,} iterations")
        print(f"   * Target EAX Value           : {solved_eax:,} (Initial 0 + {solved_N:,} * 8)")
        print(f"   * Computed EBX Final Value   : {solved_ebx:,} (Initial 500,000 - {solved_N:,} * 3)")
        print("=" * 70)


if __name__ == "__main__":
    main()
