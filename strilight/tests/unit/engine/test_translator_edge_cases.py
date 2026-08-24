import pytest
import z3

from strilight.engine.translator import Z3Translator
from strilight.engine.tracker import TraceRecord

def test_ast_depth_exhaustion():
    translator = Z3Translator()
    v = z3.BitVec("v", 64)
    translator.target_vars.add(v)
    
    # Create heavily nested AST
    expr = v
    for i in range(2000):
        expr = expr + z3.BitVecVal(1, 64)
        
    # Should not hit recursion limit
    assert translator._is_tainted(expr) == True

def test_boundary_constraints():
    translator = Z3Translator()
    v = z3.BitVec("v", 64)
    translator.target_vars.add(v)
    
    # Tainted address that is exactly 0x10000
    addr_ast = v
    
    # Force address to be exactly 0x10000
    translator.solver.add(addr_ast == 0x10000)
    
    # Read from this tainted address
    # This invokes is_tainted_addr = True
    # And it will add constraints: UGT(addr_ast, 0x10000), ULT(addr_ast, 0x00007FFFFFFFFFFF)
    # So if addr_ast == 0x10000, UGT(addr_ast, 0x10000) will be UNSAT!
    # Because UGT means strictly greater. It should probably be UGE (greater or equal).
    
    # Let's mock a TraceRecord
    record = TraceRecord(1, 0x1000, "mov", "rax, [v]", 5)
    translator.current_instr = record
    
    # Read
    res, size = translator._read_operand({'type': 'mem', 'disp': 0, 'size': 8, 'base': None, 'index': None, 'scale': 1})
    
    # Actually wait, _read_operand uses `addr_ast` from op_dict. So let's craft an op_dict that evaluates to v
    # Instead of full parse, let's just use `addr_ast` logic directly or construct op_dict that returns `v`
    
    # Mocking base reg to v
    translator.reg_state['rax'] = v
    res, size = translator._read_operand({'type': 'mem', 'disp': 0, 'size': 8, 'base': 'rax', 'index': None, 'scale': 1})
    
    assert translator.solver.check() == z3.sat

def test_mixed_aliasing():
    translator = Z3Translator()
    v = z3.BitVec("v", 32)
    translator.target_vars.add(v)
    
    # 1. Write concrete
    translator._write_operand({'type': 'mem', 'disp': 0x1000, 'size': 4, 'base': None, 'index': None, 'scale': 1}, z3.BitVecVal(0x11223344, 32))
    
    # 2. Write symbolic
    sym_addr = z3.BitVec("sym_addr", 64)
    translator.reg_state['rax'] = sym_addr
    translator._write_operand({'type': 'mem', 'disp': 0, 'size': 4, 'base': 'rax', 'index': None, 'scale': 1}, v)
    
    # 3. Read mixed
    translator.reg_state['rbx'] = z3.BitVecVal(0x1001, 64)
    val, size = translator._read_operand({'type': 'mem', 'disp': 0, 'size': 2, 'base': 'rbx', 'index': None, 'scale': 1})
    
    assert translator.solver.check() == z3.sat

