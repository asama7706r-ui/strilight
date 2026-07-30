import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.tracker import Descendant

def main():
    print("[*] AsmAnalyzer - Real Application Tracing PoC")
    
    exe_path = os.path.join(project_root, "test_app.exe")
    
    print(f"[*] Loading PE executable: {exe_path}")
    
    # Initialize Core with the full PE file
    core = AnalyzerCore(target_path=[exe_path], rootfs="D:\\work_app\\MyApp", arch="x8664", os_type="windows")
    
    # Setup tracing hooks
    setup_hooks(core)
    
    # Run emulation
    print("\n[*] Starting execution of application code...")
    core.start()
    
    if core.tracker.trace_history:
        last_tick = core.tracker.trace_history[-1].tick
        target = "eax"  # The return value from our main function
        print(f"\n[*] Slicing Trigger: Tracking '{target}' backwards from Tick {last_tick}...")
        descendant = Descendant(target=target, at_tick=last_tick, is_memory=False)
        slice_result = core.tracker.build_backward_slice(descendant)
        
        print("\n================================================")
        print("[+] Backward Slice Result (Pruning Equation):")
        print("================================================")
        for instr in reversed(slice_result):
            print(f"  {instr.tick:04d} | {instr.mnemonic:7s} {instr.op_str}")
        print("================================================")
        print("[+] This mathematical slice represents the isolated equation")
        print("    extracted from the real application binary.")
    else:
        print("[-] No trace history generated.")

if __name__ == "__main__":
    main()
