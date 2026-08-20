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
    target_exe = os.path.join(app_dir, "crackme_boss.exe")
    
    print("[*] Initializing AnalyzerCore with Speakeasy backend...")
    core = AnalyzerCore(target_path=[target_exe, "1789"])
    
    print("[*] Setting up hooks...")
    setup_hooks(core)
    
    print("[*] Starting emulation...")
    core.start()
    
    print(f"[*] Emulation completed. Total ticks traced: {core.tick_counter}")
    
    # Check if cmp is in the trace history
    target_tick = -1
    for record in reversed(core.tracker.trace_history):
        if record.mnemonic == "cmp" and ("0xde42daef" in record.op_str.lower() or "0xde13bcef" in record.op_str.lower()):
            target_tick = record.tick
            break
            
    if target_tick != -1:

         # Compress loops before building the slice
        print("\n[*] Compressing trace history...")
        core.tracker.compress_trace()

        print(f"[SUCCESS] Target CMP instruction found at Tick {target_tick}!")
        desc = Descendant(target="eax", at_tick=target_tick)
        slice_records = core.tracker.build_backward_slice(desc)
        
        print("\n[+] ===========================================")
        print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
        
        symbolic_slice = slice_records
        chronological_slice = list(reversed(symbolic_slice))
        
        # --- FULL TRACE MODE ---
        # We DO NOT truncate the slice. We translate the entire backward slice from the start!
        # start_idx = 0
        # for i in range(len(chronological_slice) - 1, -1, -1):
        #     if chronological_slice[i].mnemonic == 'push' and 'rbp' in chronological_slice[i].op_str:
        #         start_idx = i
        #         break
        # chronological_slice = chronological_slice[start_idx:]
        # print(f"[+] Truncated chronological slice to {len(chronological_slice)} instructions")
        
        translator = Z3Translator(memory_provider=core.se.mem_read)
        
        print("[+] Concretizing initial zero time moments (_t0)...")
        for reg, val in core.initial_regs.items():
            print(f"  -> Pinned {reg}_t0 = {hex(val)}")
            val_ast = z3.BitVecVal(val, 64)
            translator.reg_state[reg] = val_ast
            translator.solver.add(z3.BitVec(f"{reg}_t0", 64) == val)
            
        key_var = z3.BitVec("key_input", 32)
        translator.target_vars.add(key_var)
        translator.add_tracked_constraint(key_var >= 1000, "Key Lower Bound: key_input >= 1000")
        translator.add_tracked_constraint(key_var < 2000, "Key Upper Bound: key_input < 2000")
        
        # Clear previous assumptions
        check_key_start_tick = 0
        
        for record in chronological_slice:
            if hasattr(record, 'mnemonic') and record.mnemonic == 'push' and 'rbp' in record.op_str:
                check_key_start_tick = record.tick

        # Take a copy of the tracker data (backward slice)
        tracker_data = {r.tick: r for r in chronological_slice if hasattr(r, 'tick')}

        for record in chronological_slice:
            # 1. Force the target instruction (cmp) to generate flags because the slicer ignored it
            if record.tick == target_tick:
                record.requested_flags = ["flag_zf", "flag_cf", "flag_sf", "flag_of"]
            
            # 2. Clean the past (clear path constraints for random jumps)
            if hasattr(record, 'mnemonic') and record.mnemonic.startswith('j') and record.mnemonic != 'jmp':
                if record.tick != target_tick + 1:
                    record.jump_taken = None 

            # 3. Flip the target jump to force a win
            if record.tick == target_tick + 1:
                if record.jump_taken is not None:
                    record.jump_taken = not record.jump_taken
                    print(f"[!] Flipped target jump at Tick {record.tick} to force winning path!")
                    
            if hasattr(record, 'mnemonic'):
                translator.parse_instruction(record)
            else:
                translator.translate_loop_summary(record, max_iterations=getattr(record, 'iterations', 1000))
            
            # 4. Inject the symbolic key
            if record.tick == check_key_start_tick:
                translator.reg_state["ecx"] = key_var
                translator.reg_state["rcx"] = z3.ZeroExt(32, key_var)
                print(f"[+] Injected symbolic key into ecx at Tick {record.tick} (check_key prologue)")
        
        rax_final = translator.reg_state.get("rax", None)
        if rax_final is not None:
            print("[+] Adding Goal Constraint: rax == 0xDE42DAEF")
            translator.add_tracked_constraint(rax_final == 0xDE42DAEF, "Goal Target: rax == 0xDE42DAEF")

        print("\n[*] Z3 Solving...")
        import re
        if translator.solver.check() == z3.sat:
            model = translator.solver.model()
            print(f"\n[SUCCESS] Z3 SOLVED THE BOSS FIGHT!")
            for d in model.decls():
                var_name = d.name()
                taint_str = "(NOT_TAINTED)"
                
                # Extract register/memory name and tick using Regex
                match = re.match(r"^([a-zA-Z0-9_]+)_t(\d+)(_b\d+)?$", var_name)
                if match:
                    base_name = match.group(1)
                    tick_val = int(match.group(2))
                    
                    if tick_val in tracker_data:
                        taint_str = "(TAINTED)"
                        
                print(f"[SUCCESS] {taint_str} {var_name} = {model[d]}")
        else:
            print("\n[!] Z3 returned UNSAT. No solution found!")
            translator.explain_unsat()
    else:
        print("[-] Target not found!")

if __name__ == '__main__':
    main()
