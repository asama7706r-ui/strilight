import pytest
import z3
from strilight.engine.vsa.models import (
    LoopSummary,
    TelescopingBranch,
    TelescopingCascade,
    LoopInvariantContract,
)
from strilight.engine.translator import Z3Translator


def test_telescoping_cascade_partition_of_unity():
    """
    Validates Theorem 5.c: Telescoping Partition of Unity:
        sum_{k=1}^M P_k == 1 for any boolean indicator assignments.
    """
    solver = z3.Solver()
    c1 = z3.BitVec('c1', 64)
    c2 = z3.BitVec('c2', 64)
    c3 = z3.BitVec('c3', 64)

    # Boolean constraints: each c_i is in {0, 1}
    solver.add(z3.Or(c1 == 0, c1 == 1))
    solver.add(z3.Or(c2 == 0, c2 == 1))
    solver.add(z3.Or(c3 == 0, c3 == 1))

    # Telescoping coefficients for M=4 branches:
    P1 = c1
    P2 = (z3.BitVecVal(1, 64) - c1) * c2
    P3 = (z3.BitVecVal(1, 64) - c1) * (z3.BitVecVal(1, 64) - c2) * c3
    P_fallback = (z3.BitVecVal(1, 64) - c1) * (z3.BitVecVal(1, 64) - c2) * (z3.BitVecVal(1, 64) - c3)

    sum_P = P1 + P2 + P3 + P_fallback

    # Assert that sum_P != 1 is UNSAT (meaning sum_P == 1 is a theorem)
    solver.add(sum_P != z3.BitVecVal(1, 64))
    assert solver.check() == z3.unsat, "Telescoping Cascade must always sum to 1!"


def test_telescoping_cascade_two_branch_translation():
    """
    Validates end-to-end Z3 translation of a 2-branch if-else telescoping loop:
        if (mode == 1) eax += 10;
        else eax += 20;
    """
    summary = LoopSummary()
    summary.iterations = 100

    cascade = TelescopingCascade(target_reg="rax")
    cascade.add_branch(TelescopingBranch(
        name="branch_mode1",
        conditions=[{"lhs": "rbx", "op": "eq", "rhs": 1, "is_taken": True}],
        deltas={"rax": 10}
    ))
    cascade.add_branch(TelescopingBranch(
        name="branch_fallback",
        conditions=[],
        deltas={"rax": 20}
    ))
    summary.telescoping_cascades["rax"] = cascade

    # 1. Test when rbx == 1 -> rax increases by 10 * 100 = 1000
    translator1 = Z3Translator()
    translator1.solver.add(translator1._get_phys_reg("rax") == 0)
    translator1.solver.add(translator1._get_phys_reg("rbx") == 1)
    translator1.translate_loop_summary(summary, max_iterations=100)

    N1 = translator1.latest_loop_counter
    rax1 = translator1.reg_state['rax']

    s1 = z3.Solver()
    for a in translator1.solver.assertions():
        s1.add(a)
    s1.add(N1 == 100)
    assert s1.check() == z3.sat
    m1 = s1.model()
    assert m1[rax1].as_long() == 1000

    # 2. Test when rbx == 2 (fallback) -> rax increases by 20 * 100 = 2000
    translator2 = Z3Translator()
    translator2.solver.add(translator2._get_phys_reg("rax") == 0)
    translator2.solver.add(translator2._get_phys_reg("rbx") == 2)
    translator2.translate_loop_summary(summary, max_iterations=100)

    N2 = translator2.latest_loop_counter
    rax2 = translator2.reg_state['rax']

    s2 = z3.Solver()
    for a in translator2.solver.assertions():
        s2.add(a)
    s2.add(N2 == 100)
    assert s2.check() == z3.sat
    m2 = s2.model()
    assert m2[rax2].as_long() == 2000


def test_telescoping_cascade_four_branch_switch_case():
    """
    Validates a 4-branch switch-case cascade with symbolic solving:
        switch(key_type):
            case 0: rax += 5;
            case 1: rax += 15;
            case 2: rax += 25;
            default: rax += 35;
    """
    summary = LoopSummary()
    summary.iterations = 10

    cascade = TelescopingCascade(target_reg="rax")
    cascade.add_branch(TelescopingBranch(
        name="case_0",
        conditions=[{"lhs": "rdx", "op": "eq", "rhs": 0, "is_taken": True}],
        deltas={"rax": 5}
    ))
    cascade.add_branch(TelescopingBranch(
        name="case_1",
        conditions=[{"lhs": "rdx", "op": "eq", "rhs": 1, "is_taken": True}],
        deltas={"rax": 15}
    ))
    cascade.add_branch(TelescopingBranch(
        name="case_2",
        conditions=[{"lhs": "rdx", "op": "eq", "rhs": 2, "is_taken": True}],
        deltas={"rax": 25}
    ))
    cascade.add_branch(TelescopingBranch(
        name="case_default",
        conditions=[],
        deltas={"rax": 35}
    ))
    summary.telescoping_cascades["rax"] = cascade

    # Symbolic Goal: We start with rax = 0, iterations N = 10.
    # We want final rax to equal 250 (which requires case_2: 10 * 25 = 250).
    # Ask Z3 to solve for rdx!
    translator = Z3Translator()
    rdx_init = translator._get_phys_reg("rdx")
    translator.solver.add(translator._get_phys_reg("rax") == 0)

    translator.translate_loop_summary(summary, max_iterations=100)

    N = translator.latest_loop_counter
    rax_final = translator.reg_state['rax']

    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
    solver.add(N == 10)
    solver.add(rax_final == 250)

    assert solver.check() == z3.sat
    m = solver.model()
    solved_rdx = m[rdx_init].as_long()
    assert solved_rdx == 2, f"Expected rdx == 2 to trigger case_2, got {solved_rdx}"


def test_telescoping_cascade_nested_depth():
    """
    Validates Nested Depth (Depth 2: if (A) { if (B) { +100 } else { +50 } } else { +10 }):
        Branch 1 (A & B): delta = 100
        Branch 2 (A & !B): delta = 50
        Branch 3 (!A): delta = 10
    """
    summary = LoopSummary()
    summary.iterations = 5

    cascade = TelescopingCascade(target_reg="rax")
    # Nested Branch 1: rcx == 1 AND rdx == 1 -> +100
    cascade.add_branch(TelescopingBranch(
        name="depth2_A_and_B",
        conditions=[
            {"lhs": "rcx", "op": "eq", "rhs": 1, "is_taken": True},
            {"lhs": "rdx", "op": "eq", "rhs": 1, "is_taken": True}
        ],
        deltas={"rax": 100}
    ))
    # Nested Branch 2: rcx == 1 AND rdx != 1 -> +50
    cascade.add_branch(TelescopingBranch(
        name="depth2_A_and_not_B",
        conditions=[
            {"lhs": "rcx", "op": "eq", "rhs": 1, "is_taken": True},
            {"lhs": "rdx", "op": "ne", "rhs": 1, "is_taken": True}
        ],
        deltas={"rax": 50}
    ))
    # Outer Fallback Branch 3: rcx != 1 -> +10
    cascade.add_branch(TelescopingBranch(
        name="depth1_fallback",
        conditions=[],
        deltas={"rax": 10}
    ))
    summary.telescoping_cascades["rax"] = cascade

    # Test Branch 2 activation: rcx == 1, rdx == 0 -> +50 * 5 = 250
    translator = Z3Translator()
    translator.solver.add(translator._get_phys_reg("rax") == 0)
    translator.solver.add(translator._get_phys_reg("rcx") == 1)
    translator.solver.add(translator._get_phys_reg("rdx") == 0)

    translator.translate_loop_summary(summary, max_iterations=100)

    N = translator.latest_loop_counter
    rax_final = translator.reg_state['rax']

    solver = z3.Solver()
    for a in translator.solver.assertions():
        solver.add(a)
    solver.add(N == 5)
    solver.add(rax_final == 250)

    assert solver.check() == z3.sat


def test_telescoping_cascade_contract_serialization():
    """
    Validates LoopInvariantContract serialization with Telescoping Cascades.
    """
    summary = LoopSummary()
    summary.iterations = 50
    cascade = TelescopingCascade(target_reg="rax")
    cascade.add_branch(TelescopingBranch(name="b1", deltas={"rax": 10}))
    cascade.add_branch(TelescopingBranch(name="b2", deltas={"rax": 20}))
    summary.telescoping_cascades["rax"] = cascade

    contract = LoopInvariantContract(summary)
    d = contract.to_dict()
    assert "induction_formulas" in d
    assert "rax" in d["induction_formulas"]
    assert "telescoping_cascade" in d["induction_formulas"]["rax"]
