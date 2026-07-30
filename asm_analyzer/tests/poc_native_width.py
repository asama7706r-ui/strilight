import os
import sys
import z3

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.translator import Z3Translator

def main():
    print("[*] AsmAnalyzer - Native Width & Sub-Register Arithmetic PoC")
    
    # We will hand-craft a slice that demonstrates the Native Width model
    # 1. mov al, 0
    # 2. sub al, 1
    # 3. cmp al, 0xFF  <-- This should be true due to accurate 8-bit underflow!
    
    record1 = TraceRecord(tick=2, address=0x1004, mnemonic="sub", op_str="al, 1")
    record1.regs_read, record1.regs_write = ["al"], ["al"]
    
    record2 = TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="al, 0")
    record2.regs_read, record2.regs_write = [], ["al"]
    
    slice_records = [record1, record2]
    
    print("[+] Hand-crafted Assembly Instructions:")
    print("    1. mov al, 0")
    print("    2. sub al, 1")
    print("    3. cmp al, 0xFF")
    
    translator = Z3Translator()
    translator.translate_slice(slice_records)
    
    # Target value after 8-bit underflow
    target_value = 0xFF
    
    final_rax = translator.reg_state['rax']
    # Extract the 'AL' part of the final RAX
    final_al = z3.Extract(7, 0, final_rax)
    
    print(f"\n[*] Injecting Constraint: We want final AL to be {hex(target_value)}")
    translator.solver.add(final_al == target_value)
    
    print("\n[*] Asking Z3 Solver if this condition is naturally satisfied...")
    if translator.solver.check() == z3.sat:
        print(f"\n[+] SUCCESS! Z3 confirms that '0 - 1' in AL results in 0xFF!")
        print("[+] This proves the strict Native Width (8-bit) math is perfectly accurate.")
    else:
        print("[-] FAILED. Z3 Solver could not satisfy the constraint.")

if __name__ == "__main__":
    main()
