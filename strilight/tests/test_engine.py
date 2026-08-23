import sys
import os
import z3

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)

from strilight.engine.core import AnalyzerCore
from strilight.engine.hooks import setup_hooks
from strilight.engine.tracker import Descendant
from strilight.engine.translator import Z3Translator

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
        
        # Compress loops before building the slice
        print("\n[*] Compressing trace history...")
        core.tracker.compress_trace()
        
        desc = Descendant(target="eax", at_tick=target_tick)
        slice_records = core.tracker.build_backward_slice(desc)
        
        print("\n[+] ===========================================")
        print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
        
        symbolic_slice = slice_records
        chronological_slice = list(reversed(symbolic_slice))
        
        # Truncate to check_key (last push rbp before target)
        start_idx = 0
        for i in range(len(chronological_slice) - 1, -1, -1):
            if hasattr(chronological_slice[i], 'mnemonic') and chronological_slice[i].mnemonic == 'push' and 'rbp' in chronological_slice[i].op_str:
                start_idx = i
                break
        chronological_slice = chronological_slice[start_idx:]
        print(f"[+] Truncated chronological slice to {len(chronological_slice)} instructions")
        
        translator = Z3Translator(memory_provider=core.se.mem_read)
        key_var = z3.BitVec("key_input", 32)
        
        # Inject key at the very beginning of the truncated slice
        translator.reg_state["ecx"] = key_var
        translator.reg_state["rcx"] = z3.ZeroExt(32, key_var)
        print("[+] Injected symbolic key into ecx")
        
        for record in chronological_slice:
            if hasattr(record, 'tick') and record.tick == target_tick + 1:
                if hasattr(record, 'jump_taken') and record.jump_taken is not None:
                    record.jump_taken = not record.jump_taken
                    print(f"[!] Flipped target jump at Tick {record.tick} to force winning path!")
                    
        # Now pass the slice to translate_slice (it expects reverse chronological)
        final_slice_for_translation = list(reversed(chronological_slice))
        translator.translate_slice(final_slice_for_translation)
        
        rax_final = translator.reg_state.get("rax", None)
        if rax_final is not None:
            print("[+] Adding Goal Constraint: rax == 0xDE1770EF")
            translator.solver.add(rax_final == 0xDE1770EF)
        
        print("\n[*] Z3 Solving...")
        import time
        start_time = time.time()
        res = translator.solver.check()
        end_time = time.time()
        print(f"[*] Z3 Solving Time: {end_time - start_time:.4f} seconds")
        if res == z3.sat:
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
