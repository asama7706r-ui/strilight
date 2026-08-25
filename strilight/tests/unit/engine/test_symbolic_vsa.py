import pytest
from strilight.engine.vsa_evaluator import LoopEvaluator, LoopSummary, AffineExpr, RegisterCouplingMatrix
from strilight.engine.loop_compressor import LoopBlock
from strilight.engine.instruction import Instruction


def test_affine_expr_operations():
    """Test basic arithmetic operations on AffineExpr."""
    e1 = AffineExpr.from_reg("rax")  # 1 * rax + 0
    e2 = AffineExpr.from_const(5)    # 5
    
    # rax + 5
    e3 = e1.add(e2)
    assert e3.coeffs == {"rax": 1}
    assert e3.offset == 5
    assert e3.get_scalar_delta("rax") == 5
    
    # (rax + 5) + (2 * rbx - 3)
    e4 = AffineExpr({"rbx": 2}, -3)
    e5 = e3.add(e4)
    assert e5.coeffs == {"rax": 1, "rbx": 2}
    assert e5.offset == 2


def test_register_coupling_matrix():
    """Test RegisterCouplingMatrix (Rule 7 from Notion)."""
    regs = ["rax", "rbx", "rcx"]
    mat = RegisterCouplingMatrix(regs)
    assert mat.is_identity()
    
    # rax' = rax + rbx + 4
    mat.set_affine_row("rax", AffineExpr({"rax": 1, "rbx": 1}, 4))
    assert not mat.is_identity()
    assert mat.matrix[mat.reg_to_idx["rax"]] == [1, 1, 0]
    assert mat.offset[mat.reg_to_idx["rax"]] == 4


def test_symbolic_single_pass_linear_loop():
    """
    Test that LoopEvaluator extracts deltas in a single symbolic pass without 100 iterations.
    Loop:
        add ecx, 1
        add eax, 4
    """
    inst1 = Instruction(address=0x1000, mnemonic="add", op_str="ecx, 1",
                        regs_read=["ecx"], regs_write=["ecx"], operands=[
                            {"type": "reg", "value": "ecx"},
                            {"type": "imm", "value": 1}
                        ])
    inst2 = Instruction(address=0x1004, mnemonic="add", op_str="eax, 4",
                        regs_read=["eax"], regs_write=["eax"], operands=[
                            {"type": "reg", "value": "eax"},
                            {"type": "imm", "value": 4}
                        ])
    
    block = LoopBlock(body=[inst1, inst2], iterations=10000)
    
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(block)
    
    assert summary.deltas.get("ecx") == 1
    assert summary.deltas.get("eax") == 4
    assert summary.iterations == 10000


def test_symbolic_geometric_shift_loop():
    """
    Test that LoopEvaluator extracts geometric shift recurrence (Rule 6) from:
        shl r8d, cl
        add edx, r8d
        add ecx, 1
    """
    inst1 = Instruction(address=0x1000, mnemonic="shl", op_str="r8d, cl",
                        regs_read=["r8d", "cl", "rcx", "ecx"], regs_write=["r8d"], operands=[
                            {"type": "reg", "value": "r8d"},
                            {"type": "reg", "value": "cl"}
                        ])
    inst2 = Instruction(address=0x1004, mnemonic="add", op_str="edx, r8d",
                        regs_read=["edx", "r8d"], regs_write=["edx"], operands=[
                            {"type": "reg", "value": "edx"},
                            {"type": "reg", "value": "r8d"}
                        ])
    inst3 = Instruction(address=0x1008, mnemonic="add", op_str="ecx, 1",
                        regs_read=["ecx"], regs_write=["ecx"], operands=[
                            {"type": "reg", "value": "ecx"},
                            {"type": "imm", "value": 1}
                        ])
                        
    block = LoopBlock(body=[inst1, inst2, inst3], iterations=10000)
    
    evaluator = LoopEvaluator()
    summary = evaluator.evaluate(block)
    
    assert summary.deltas.get("ecx") == 1
    assert "edx" in summary.geometric_shifts or "r8d" in summary.geometric_shifts
