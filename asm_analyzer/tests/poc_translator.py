import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.tracker import Descendant
from asm_analyzer.engine.translator import Z3Translator

def main():
    print("[*] AsmAnalyzer - SMT Translation (Physical Backing Model) PoC")
    
    exe_path = os.path.join(project_root, "test_app.exe")
    
    print(f"[*] Loading PE executable: {exe_path}")
    core = AnalyzerCore(target_path=[exe_path], rootfs="D:\\work_app\\MyApp", arch="x8664", os_type="windows")
    
    setup_hooks(core)
    
    print("\n[*] Starting execution...")
    core.start()
    
    if core.tracker.trace_history:
        last_tick = core.tracker.trace_history[-1].tick
        target = "eax"  # The return value from our main function
        
        print(f"\n[*] Slicing Trigger: Tracking '{target}' backwards from Tick {last_tick}...")
        descendant = Descendant(target=target, at_tick=last_tick, is_memory=False)
        slice_result = core.tracker.build_backward_slice(descendant)
        
        # Now pass the slice to the Translator
        translator = Z3Translator()
        translator.translate_slice(slice_result)
        
        print("\n[*] Asking Z3 Solver for answers (Model Evaluation)...")
        if translator.solver.check() == z3.sat:
            m = translator.solver.model()
            final_rax = translator.reg_state['rax']
            # We only care about the lower 32 bits since the target was eax
            final_eax = z3.Extract(31, 0, final_rax)
            result = m.eval(final_eax)
            print(f"[+] Z3 Solved Result for EAX: {result.as_long()} (Hex: {hex(result.as_long())})")
        else:
            print("[-] Z3 Solver could not find a solution (Unsatisfiable).")

        
    else:
        print("[-] No trace history generated.")

if __name__ == "__main__":
    main()
