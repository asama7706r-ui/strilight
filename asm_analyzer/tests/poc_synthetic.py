import os
import sys
import z3

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.translator import Z3Translator

def main():
    print("[*] AsmAnalyzer - Synthetic Symbolic Execution PoC")
    
    # We will hand-craft a Backward Slice (reverse-chronological order).
    # Imagine the assembly was:
    # 1. xor eax, 0x1337      <-- (User Input is initially in eax)
    # 2. add eax, 0x42
    # 3. cmp eax, 0xCAFEBABE  <-- We want this to be true!
    
    record1 = TraceRecord(tick=2, address=0x1004, mnemonic="add", op_str="eax, 0x42")
    record1.regs_read, record1.regs_write = ["eax"], ["eax"]
    
    record2 = TraceRecord(tick=1, address=0x1000, mnemonic="xor", op_str="eax, 0x1337")
    record2.regs_read, record2.regs_write = ["eax"], ["eax"]
    
    slice_records = [record1, record2]
    
    print("[+] Hand-crafted Assembly Instructions:")
    print("    1. xor eax, 0x1337")
    print("    2. add eax, 0x42")
    print("    3. cmp eax, 0xCAFEBABE")
    
    translator = Z3Translator()
    
    # Translate the slice into Z3 Math
    translator.translate_slice(slice_records)
    
    # The initial symbolic input is the first version of RAX (rax_0)
    # This represents the user's input before any operations.
    initial_rax = translator.reg_state['rax'] if 'rax' in translator.reg_state else z3.BitVec('rax_0', 64)
    # Actually, translator initializes variables lazily. Let's get the earliest one, which is rax_0.
    # We can retrieve it by creating a BitVec with the same name.
    initial_eax = z3.Extract(31, 0, z3.BitVec('rax_0', 64))
    
    # The final state of RAX after all operations
    final_rax = translator.reg_state['rax']
    final_eax = z3.Extract(31, 0, final_rax)
    
    # Inject the CMP condition: We want the final EAX to equal 0xCAFEBABE
    target_value = 0xCAFEBABE
    print(f"\n[*] Injecting Constraint: We want final EAX to be {hex(target_value)}")
    translator.solver.add(final_eax == target_value)
    
    print("\n[*] Asking Z3 Solver for the required Initial Input (eax_0)...")
    if translator.solver.check() == z3.sat:
        m = translator.solver.model()
        solution = m.eval(initial_eax)
        print(f"\n[+] SUCCESS! Z3 found the required input!")
        print(f"[+] To bypass the CMP, the initial EAX must be: {hex(solution.as_long())}")
        
        # Let's verify mathematically
        val = solution.as_long()
        print("\n[*] Manual Verification:")
        val = val ^ 0x1337
        print(f"    After XOR 0x1337: {hex(val)}")
        val = (val + 0x42) & 0xFFFFFFFF
        print(f"    After ADD 0x42  : {hex(val)}")
        if val == target_value:
            print(f"    Result == {hex(target_value)} (Target Reached!)")
        
    else:
        print("[-] Z3 Solver could not find a solution (Unsatisfiable).")

if __name__ == "__main__":
    main()
