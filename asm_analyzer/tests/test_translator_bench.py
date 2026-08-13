import time
import z3

from asm_analyzer.engine.translator import Z3Translator
from asm_analyzer.engine.tracker import TraceRecord

def test_performance():
    translator = Z3Translator()
    
    # Create dummy instructions
    # 'mov' is near the top
    instr_top = TraceRecord(tick=1, address=0x1000, size=2, mnemonic='mov', op_str='rax, rbx')
    instr_top.regs_read = ['rbx']
    instr_top.regs_write = ['rax']
    instr_top.operands = [{'type': 'reg', 'value': 'rax', 'size': 8}, {'type': 'reg', 'value': 'rbx', 'size': 8}]
    
    # 'xchg' is near the bottom
    instr_bot = TraceRecord(tick=2, address=0x1002, size=2, mnemonic='xchg', op_str='rax, rbx')
    instr_bot.regs_read = ['rax', 'rbx']
    instr_bot.regs_write = ['rax', 'rbx']
    instr_bot.operands = [{'type': 'reg', 'value': 'rax', 'size': 8}, {'type': 'reg', 'value': 'rbx', 'size': 8}]

    # unhandled
    instr_un = TraceRecord(tick=3, address=0x1004, size=2, mnemonic='unhandled', op_str='')
    
    N = 10000
    
    # Profile worst case ('xchg')
    t0 = time.time()
    for _ in range(N):
        translator.parse_instruction(instr_bot)
    t1 = time.time()
    print(f"Time for {N} calls (worst-case 'xchg'): {t1 - t0:.6f} s")
    
    # Profile best case ('mov')
    t0 = time.time()
    for _ in range(N):
        translator.parse_instruction(instr_top)
    t1 = time.time()
    print(f"Time for {N} calls (best-case 'mov'): {t1 - t0:.6f} s")

    # Profile unhandled 
    t0 = time.time()
    for _ in range(N):
        translator.parse_instruction(instr_un)
    t1 = time.time()
    print(f"Time for {N} calls (unhandled): {t1 - t0:.6f} s")

if __name__ == '__main__':
    test_performance()
