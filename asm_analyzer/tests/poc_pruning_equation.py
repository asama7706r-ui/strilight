import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.tracker import Descendant
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def compile_c_loop_to_shellcode() -> bytes:
    """
    Equivalent to the C code:
    int main() {
        int key = 0x55;
        int data = 0;
        for (int i = 0; i < 3; i++) {
            data += key ^ i;
        }
        return data;
    }
    """
    asm = b"mov rbx, 0x55; xor rax, rax; xor rcx, rcx; loop_start: cmp rcx, 3; jge loop_end; mov rdx, rbx; xor rdx, rcx; add rax, rdx; add rcx, 1; jmp loop_start; loop_end: nop;"
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(asm)
    return bytes(encoding)

def main():
    print("[*] AsmAnalyzer - Loop Compression (Pruning Equation) PoC")
    
    # 1. Compile the C-equivalent loop to binary machine code
    code = compile_c_loop_to_shellcode()
    print(f"[+] Compiled Application Loop to {len(code)} bytes of machine code.")
    
    # 2. Initialize AnalyzerCore
    core = AnalyzerCore(code=code, rootfs="D:\\work_app\\MyApp", arch="x8664", os_type="linux")
    setup_hooks(core)
    
    print("\n[*] Starting execution...")
    core.start()
    
    if core.tracker.trace_history:
        last_tick = core.tracker.trace_history[-1].tick
        target = "rax"  # Return value (data)
        
        print(f"\n[*] Slicing Trigger: Tracking '{target}' backwards from Tick {last_tick}...")
        descendant = Descendant(target=target, at_tick=last_tick, is_memory=False)
        slice_result = core.tracker.build_backward_slice(descendant)
        
        print("\n================================================")
        print("[+] Backward Slice Result (Pruning Equation Generation):")
        print("================================================")
        for instr in reversed(slice_result):
            print(f"  Tick {instr.tick:04d} | {instr.mnemonic:7s} {instr.op_str}")
        print("================================================")
        print("[+] This mathematical slice isolates the exact operations")
        print("    that affected the final return value (data), effectively")
        print("    compressing the loop into a pure algebraic equation for Z3!")
    else:
        print("[-] No trace history generated.")

if __name__ == "__main__":
    main()
