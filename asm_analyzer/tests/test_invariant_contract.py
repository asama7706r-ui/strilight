"""
Unit tests for LoopInvariantContract in LoopSummary.
Verifies:
1. Structural Invariant Formulas at iteration N and N-1.
2. Iron Constraint Exit Predicate Rule Generation.
3. Serialization of the contract via to_dict().
"""

import pytest
from asm_analyzer.engine.vsa_evaluator import LoopSummary, LoopInvariantContract
from asm_analyzer.engine.instruction import Instruction


def test_loop_invariant_contract_formulas():
    summary = LoopSummary()
    summary.deltas["eax"] = 8
    summary.deltas["ebx"] = -3
    summary.patterns["ecx"] = [5, 4]
    summary.constant_sets["edx"] = 100
    summary.exit_condition = "[cmp ecx, 1000] -> jle"
    summary.iterations = 500
    summary.exit_records = [
        Instruction(address=0x1000, mnemonic="cmp", op_str="ecx, 1000"),
        Instruction(address=0x1006, mnemonic="jle", op_str="0x1000")
    ]
    
    contract = summary.invariant_contract
    assert contract is not None
    
    formulas = contract.get_induction_formulas()
    assert "eax" in formulas
    assert formulas["eax"]["formula_at_N"] == "eax_0 + (8) * N"
    assert formulas["eax"]["formula_at_N_minus_1"] == "eax_0 + (8) * (N - 1)"
    
    assert "ebx" in formulas
    assert formulas["ebx"]["formula_at_N"] == "ebx_0 + (-3) * N"
    assert formulas["ebx"]["formula_at_N_minus_1"] == "ebx_0 + (-3) * (N - 1)"
    
    assert "ecx" in formulas
    assert formulas["ecx"]["period"] == 2
    assert formulas["ecx"]["cycle_sum"] == 9
    
    assert "edx" in formulas
    assert formulas["edx"]["formula_at_N"] == "100"
    
    rule = contract.get_exit_invariant_rule()
    assert "Iron Constraint" in rule
    assert "State(N) == True" in rule
    assert "State(N-1) == False" in rule
    
    contract_dict = contract.to_dict()
    assert contract_dict["exit_condition_text"] == "[cmp ecx, 1000] -> jle"
    assert len(contract_dict["exit_instructions"]) == 2
    assert contract_dict["iterations_bound"] == 500
