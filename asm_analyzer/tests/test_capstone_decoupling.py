"""
Test Suite verifying the Decoupled Core Compressor with native Capstone integration.
Tests:
1. Direct Machine Bytes Disassembly via Capstone -> Instruction
2. Loop Compression & VSA Evaluation from Capstone Instructions
3. Pluggable Custom Tracer on TrackerBridge
"""

import pytest
import capstone
from asm_analyzer.engine.instruction import Instruction
from asm_analyzer.engine.loop_compressor import LoopBlock, TraceCompressor
from asm_analyzer.engine.vsa_evaluator import LoopEvaluator
from asm_analyzer.engine.tracker_bridge import TrackerBridge
from asm_analyzer.pruning.interval import Interval


def test_instruction_from_capstone():
    """
    Tests converting raw machine code bytes into Instruction objects via Capstone.
    """
    # 64-bit x86 instructions:
    # add eax, 4 -> 83 c0 04
    # sub ebx, 2 -> 83 eb 02
    # inc ecx    -> ff c1
    # cmp ecx, 1000 -> 81 f9 e8 03 00 00
    # jle -18    -> 7e ee
    code_bytes = bytes.fromhex("83c004" "83eb02" "ffc1" "81f9e8030000" "7eee")
    
    instructions = Instruction.disassemble_bytes(code_bytes, base_address=0x1000, bit_mode=64)
    assert len(instructions) == 5
    
    assert instructions[0].mnemonic == "add"
    assert instructions[0].op_str == "eax, 4"
    assert instructions[0].address == 0x1000
    
    assert instructions[1].mnemonic == "sub"
    assert instructions[1].op_str == "ebx, 2"
    
    assert instructions[2].mnemonic == "inc"
    assert instructions[2].op_str == "ecx"
    
    assert instructions[3].mnemonic == "cmp"
    assert instructions[3].op_str == "ecx, 0x3e8"
    
    assert instructions[4].mnemonic == "jle"


def test_core_loop_evaluation_from_capstone_bytes():
    """
    Tests end-to-end evaluation of raw machine code bytes into LoopSummary.
    """
    # Loop body:
    # add eax, 8
    # sub edx, 3
    # inc ecx
    # cmp ecx, 500
    # jl 0x1000
    code_bytes = bytes.fromhex("83c008" "83ea03" "ffc1" "81f9f4010000" "7cee")
    instructions = Instruction.disassemble_bytes(code_bytes, base_address=0x1000, bit_mode=64)
    
    loop_block = LoopBlock(body=instructions, iterations=500)
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(loop_block)
    
    assert summary is not None
    assert "eax" in summary.deltas
    assert summary.deltas["eax"] == 8
    
    assert "edx" in summary.deltas
    assert summary.deltas["edx"] == -3
    
    assert "ecx" in summary.deltas
    assert summary.deltas["ecx"] == 1
    
    assert summary.exit_condition is not None
    assert "cmp" in summary.exit_condition
    assert "jl" in summary.exit_condition


def test_custom_tracer_registration_on_bridge():
    """
    Tests registering an external custom tracer on TrackerBridge.
    """
    class MockCustomTracer:
        def evaluate_loop_exit(self, loop_block, induction_vars):
            return "CUSTOM_EXIT_CONDITION", ["MOCK_RECORD"]
            
    TrackerBridge.register_tracer(MockCustomTracer())
    
    cond_str, records = TrackerBridge.evaluate_loop_exit(LoopBlock(body=[], iterations=10))
    assert cond_str == "CUSTOM_EXIT_CONDITION"
    assert records == ["MOCK_RECORD"]
    
    # Reset custom tracer
    TrackerBridge.register_tracer(None)
