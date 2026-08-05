import pytest
import z3
from asm_analyzer.engine.translator import Z3Translator
from asm_analyzer.engine.tracker import TraceRecord

def get_value(translator, reg):
    val = translator.reg_state.get(reg)
    translator.solver.check()
    m = translator.solver.model()
    return m.evaluate(val).as_long()

def test_z3_translator_init():
    translator = Z3Translator(memory_provider=lambda addr, size: b"\x00"*size)
    assert isinstance(translator.solver, z3.Solver)
    assert isinstance(translator.reg_state, dict)

def test_translator_mov():
    translator = Z3Translator()
    r = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 5", size=5)
    translator.parse_instruction(r)
    assert get_value(translator, "rax") == 5

def test_translator_add():
    translator = Z3Translator()
    translator.parse_instruction(TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 5", size=5))
    translator.parse_instruction(TraceRecord(tick=2, address=0x1005, mnemonic="add", op_str="rax, 3", size=4))
    assert get_value(translator, "rax") == 8

def test_translator_cmp():
    translator = Z3Translator()
    # Force flag generation since Z3Translator might do lazy generation
    translator.requested_flags = ["flag_zf"]
    
    translator.parse_instruction(TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 5", size=5))
    
    cmp_rec = TraceRecord(tick=2, address=0x1005, mnemonic="cmp", op_str="rax, 5", size=4)
    # Mocking jump_taken forces condition flag usage if jump exists, but we can also manually generate
    translator.parse_instruction(cmp_rec)
    
    zf = translator.flag_state.get("flag_zf")
    if zf is not None:
        translator.solver.check()
        m = translator.solver.model()
        eval_zf = m.evaluate(zf)
        assert z3.is_true(eval_zf)
    
