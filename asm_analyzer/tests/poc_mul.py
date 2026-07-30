import os
import sys
import z3

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.translator import Z3Translator

def main():
    print("[*] AsmAnalyzer - Implicit Sub-Register Entanglement PoC (MUL)")
    
    # We will hand-craft a slice that demonstrates the MUL implicit behavior
    # We want to solve this backward:
    # 1. mov eax, 0x12345678  (Target number)
    # 2. mov ecx, 0x2         (Multiplier)
    # 3. mul ecx              (Does EAX * ECX, stores in EDX:EAX)
    # 4. cmp edx, 0           (Checking for overflow into EDX)
    
    record3 = TraceRecord(tick=3, address=0x1008, mnemonic="mul", op_str="ecx")
    record3.regs_read, record3.regs_write = ["ecx", "eax"], ["eax", "edx", "eflags"]
    
    record2 = TraceRecord(tick=2, address=0x1004, mnemonic="mov", op_str="ecx, 0x20000000")
    record2.regs_read, record2.regs_write = [], ["ecx"]
    
    record1 = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="eax, 0x10000000")
    record1.regs_read, record1.regs_write = [], ["eax"]
    
    slice_records = [record3, record2, record1]
    
    print("[+] Hand-crafted Assembly Instructions:")
    print("    1. mov eax, 0x10000000")
    print("    2. mov ecx, 0x20000000")
    print("    3. mul ecx")
    
    translator = Z3Translator()
    translator.translate_slice(slice_records)
    
    final_edx = z3.Extract(31, 0, translator.reg_state['rdx'])
    final_eax = z3.Extract(31, 0, translator.reg_state['rax'])
    
    print("\n[*] Injecting Constraint: We want to find the resulting EDX and EAX")
    
    if translator.solver.check() == z3.sat:
        m = translator.solver.model()
        edx_val = m.eval(final_edx)
        eax_val = m.eval(final_eax)
        
        print(f"\n[+] SUCCESS! Z3 computed the exact values across EDX:EAX!")
        print(f"    EDX = {hex(edx_val.as_long())}")
        print(f"    EAX = {hex(eax_val.as_long())}")
        
        # Manual verification
        val1 = 0x10000000
        val2 = 0x20000000
        real_mul = val1 * val2
        real_edx = (real_mul >> 32) & 0xFFFFFFFF
        real_eax = real_mul & 0xFFFFFFFF
        
        print("\n[*] Manual Verification (0x10000000 * 0x20000000):")
        print(f"    EDX should be: {hex(real_edx)}")
        print(f"    EAX should be: {hex(real_eax)}")
        
        if edx_val.as_long() == real_edx and eax_val.as_long() == real_eax:
            print("    -> PERFECT MATCH! Mathematical entanglement works across physical registers.")
    else:
        print("[-] FAILED. Z3 Solver could not satisfy the constraint.")

if __name__ == "__main__":
    main()
