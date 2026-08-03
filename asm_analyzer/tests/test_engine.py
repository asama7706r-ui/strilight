import sys
import os
import z3

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.tracker import Descendant
from asm_analyzer.engine.translator import Z3Translator

def main():
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    print("[*] Initializing AnalyzerCore with Speakeasy backend...")
    core = AnalyzerCore(target_path=[target_exe, "5001"])
    
    print("[*] Setting up hooks...")
    setup_hooks(core)
    
    print("[*] Starting emulation...")
    core.start()
    
    print(f"[*] Emulation completed. Total ticks traced: {core.tick_counter}")
    
    # Check if cmp is in the trace history
    target_tick = -1
    for record in reversed(core.tracker.trace_history):
        if record.mnemonic == "cmp" and "0xde1770ef" in record.op_str.lower():
            target_tick = record.tick
            break
            
    if target_tick != -1:
        print(f"[SUCCESS] Target CMP instruction found at Tick {target_tick}!")
        desc = Descendant(target="eax", at_tick=target_tick)
        slice_records = core.tracker.build_backward_slice(desc)
        
        print("\n[+] ===========================================")
        print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
        
        symbolic_slice = slice_records
        chronological_slice = list(reversed(symbolic_slice))
        
        # Truncate to check_key (last push rbp before target)
        start_idx = 0
        for i in range(len(chronological_slice) - 1, -1, -1):
            if chronological_slice[i].mnemonic == 'push' and 'rbp' in chronological_slice[i].op_str:
                start_idx = i
                break
        chronological_slice = chronological_slice[start_idx:]
        print(f"[+] Truncated chronological slice to {len(chronological_slice)} instructions")
        
        translator = Z3Translator()
        key_var = z3.BitVec("key_input", 32)
        injected = False
        
        for record in chronological_slice:
            if record.tick == target_tick + 1:
                if record.jump_taken is not None:
                    record.jump_taken = not record.jump_taken
                    print(f"[!] Flipped target jump at Tick {record.tick} to force winning path!")
                    
            translator.parse_instruction(record)
            
            # Inject key at the start of check_key (first push rbp)
            if not injected and record.mnemonic == "push" and "rbp" in record.op_str:
                translator.reg_state["ecx"] = key_var
                translator.reg_state["rcx"] = z3.ZeroExt(32, key_var)
                injected = True
                print(f"[+] Injected symbolic key into ecx at Tick {record.tick}")
        
        rax_final = translator.reg_state.get("rax", None)
        if rax_final is not None:
            print("[+] Adding Goal Constraint: rax == 0xDE1770EF")
            translator.solver.add(rax_final == 0xDE1770EF)
        
        print("\n[*] Z3 Solving...")
        if translator.solver.check() == z3.sat:
            model = translator.solver.model()
            print(f"\n[SUCCESS] Z3 SOLVED THE BOSS FIGHT!")
            for d in model.decls():
                print(f"[SUCCESS] {d.name()} = {model[d]}")
        else:
            print("\n[!] Z3 returned UNSAT. No solution found!")
    else:
        print("[-] Target not found!")

if __name__ == '__main__':
    main()
