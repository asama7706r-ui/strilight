import os
import sys

# Ensure the root of the project is in sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def compile_shellcode(assembly: str) -> bytes:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(assembly)
    return bytes(encoding)

def main():
    print("[*] AsmAnalyzer - Complex PoC (Loops & Math)")
    
    # Complex Assembly Algorithm:
    # Mimics a C++ loop: 
    # int max_val = 0;
    # for(int i=0; i<3; i++) {
    #     int val = (i * 7) % 15;
    #     if (val > max_val) max_val = val;
    # }
    # if (max_val == 14) { ... }
    
    asm_code = (
        "mov rcx, 3;"         # Loop counter (3 iterations)
        "mov r8, 0;"          # Index (i)
        "mov r9, 0;"          # max_val
        
        "loop_start:"
        "cmp r8, rcx;"        # Check if i < 3
        "jge loop_end;"       # If i >= 3, exit loop
        
        # val = (i * 7) % 15
        "mov rax, r8;"
        "imul rax, 7;"
        "mov rdx, 0;"         # Clear high bits for div
        "mov rbx, 15;"
        "div rbx;"            # rax = rax / 15, rdx = rax % 15
        
        # if (val > max_val)
        "cmp rdx, r9;"
        "jle skip_update;"
        "mov r9, rdx;"        # max_val = val
        
        "skip_update:"
        "inc r8;"             # i++
        "jmp loop_start;"
        
        "loop_end:"
        "mov rax, r9;"        # Target descendant setup
        "cmp rax, 14;"        # TICK OF INTEREST: We will track 'rax' backwards from here
        "je target_reached;"
        "nop;"
        "target_reached:"
        "nop;"
    )
    
    print("[*] Compiling complex shellcode...")
    shellcode = compile_shellcode(asm_code)
    
    print("[*] Initializing Analyzer Core...")
    core = AnalyzerCore(
        code=shellcode,
        rootfs=".",
        arch="x8664",
        os_type="windows"
    )
    
    setup_hooks(core)
    core.start()

if __name__ == "__main__":
    main()
