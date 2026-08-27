import pytest
import z3
from strilight.engine.stack_engine import SymbolicStackEngine, StackByteCell


def test_stack_push_pop_concrete():
    engine = SymbolicStackEngine()
    initial_rsp = z3.BitVecVal(0x7FFFFFF0, 64)
    val = 0x1122334455667788

    new_rsp, _ = engine.push(initial_rsp, val, size_bytes=8, origin_instr="push_1", timestamp=10)
    assert z3.simplify(new_rsp).as_long() == 0x7FFFFFF0 - 8

    final_rsp, popped_ast = engine.pop(new_rsp, size_bytes=8, origin_instr="pop_1", timestamp=20)
    assert z3.simplify(final_rsp).as_long() == 0x7FFFFFF0

    s = z3.Solver()
    s.add(popped_ast == z3.BitVecVal(val, 64))
    assert s.check() == z3.sat


def test_stack_push_pop_symbolic():
    engine = SymbolicStackEngine()
    initial_rsp = z3.BitVecVal(0x7FFFFFF0, 64)
    key_var = z3.BitVec("secret_key", 64)

    new_rsp, _ = engine.push(initial_rsp, key_var, size_bytes=8, origin_instr="push_key", timestamp=100, is_tainted=True)
    final_rsp, popped_ast = engine.pop(new_rsp, size_bytes=8, origin_instr="pop_key", timestamp=105)

    s = z3.Solver()
    s.add(key_var == 0xCAFEBABE12345678)
    s.add(popped_ast == 0xCAFEBABE12345678)
    assert s.check() == z3.sat


def test_partial_overlap_stitching():
    engine = SymbolicStackEngine()
    base_addr = 0x1000

    # 1. Write 4 bytes: 0xDEADBEEF at 0x1000
    engine.write_val(base_addr, 0xDEADBEEF, size_bytes=4, origin_instr="mov_dword", timestamp=1)

    # 2. Overwrite 2 bytes at 0x1001: 0x42DA
    engine.write_val(base_addr + 1, 0x42DA, size_bytes=2, origin_instr="mov_word", timestamp=2)

    # 3. Read 4 bytes at 0x1000
    # Expected in Little-Endian:
    # byte 0 (0x1000): 0xEF (from write 1)
    # byte 1 (0x1001): 0xDA (from write 2, LSB)
    # byte 2 (0x1002): 0x42 (from write 2, MSB)
    # byte 3 (0x1003): 0xDE (from write 1)
    # Full word: 0xDE42DAEF
    read_ast = engine.read_val(base_addr, size_bytes=4, tick=3)
    simp_val = z3.simplify(read_ast)
    assert isinstance(simp_val, z3.BitVecNumRef)
    assert hex(simp_val.as_long()) == hex(0xDE42DAEF)


def test_provenance_tracking():
    engine = SymbolicStackEngine()
    base_addr = 0x2000

    engine.write_val(base_addr, 0xDEADBEEF, size_bytes=4, origin_instr="instr_a", timestamp=10)
    engine.write_val(base_addr + 1, 0x99, size_bytes=1, origin_instr="instr_b", timestamp=20)

    prov = engine.get_provenance(base_addr, size_bytes=4, tick=25)
    assert len(prov) == 4
    assert prov[0]['origin_instr'] == "instr_a"
    assert prov[0]['timestamp'] == 10
    assert prov[1]['origin_instr'] == "instr_b"
    assert prov[1]['timestamp'] == 20
    assert prov[2]['origin_instr'] == "instr_a"
    assert prov[3]['origin_instr'] == "instr_a"


def test_frame_slot_relative_access():
    engine = SymbolicStackEngine()
    rbp = z3.BitVecVal(0x7FFFFFF0, 64)

    # Write [rbp - 8] = 0x1337
    engine.write_slot(rbp, -8, 0x1337, size_bytes=4, origin_instr="mov_slot", timestamp=50)

    # Read [rbp - 8]
    val_ast, cells = engine.read_slot(rbp, -8, size_bytes=4, tick=55)
    assert z3.simplify(val_ast).as_long() == 0x1337
    assert len(cells) == 4
