"""
Unit tests for strilight High-Level Facade API (sl.disassemble, sl.compress, sl.evaluate, sl.analyze).
"""

import pytest
import strilight as sl


def test_facade_disassemble():
    raw_bytes = bytes.fromhex("83c00883eb03")
    insns = sl.disassemble(raw_bytes, base_address=0x1000)
    assert len(insns) == 2
    assert insns[0].mnemonic == "add"
    assert insns[1].mnemonic == "sub"


def test_facade_compress():
    raw_bytes = bytes.fromhex("83c008")
    insn = sl.disassemble(raw_bytes)[0]
    trace = [insn] * 10
    compressed = sl.compress(trace, min_iterations=3)
    assert len(compressed) == 1
    assert isinstance(compressed[0], sl.LoopBlock)
    assert compressed[0].iterations == 10


def test_facade_evaluate():
    raw_bytes = bytes.fromhex("83c00883eb03ffc181f9a08601007ced")
    insns = sl.disassemble(raw_bytes, base_address=0x1000)
    
    # 1. Evaluate with LoopBlock
    block = sl.LoopBlock(body=insns, iterations=100000)
    summary = sl.evaluate(block)
    assert summary.deltas.get("eax") == 8
    assert summary.deltas.get("ebx") == -3
    assert summary.deltas.get("ecx") == 1
    
    # 2. Evaluate directly with list of instructions
    summary2 = sl.evaluate(insns, iterations=50000)
    assert summary2.deltas.get("eax") == 8


def test_facade_analyze_one_liner():
    # Loop body: add eax, 8; sub ebx, 3; inc ecx; cmp ecx, 100000; jl 0x1000
    loop_bytes = bytes.fromhex("83c008" "83eb03" "ffc1" "81f9a0860100" "7ced")
    
    # ONE-LINE ANALYSIS:
    summary = sl.analyze(loop_bytes, iterations=100000)
    
    assert summary.deltas["eax"] == 8
    assert summary.deltas["ebx"] == -3
    assert summary.deltas["ecx"] == 1
    
    contract = summary.invariant_contract
    assert contract is not None
    formulas = contract.get_induction_formulas()
    assert formulas["eax"]["formula_at_N"] == "eax_0 + (8) * N"
