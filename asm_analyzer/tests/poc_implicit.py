import os
import sys

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
    print("[*] AsmAnalyzer - Implicit Flow PoC")
    
    # We will simulate a Taint Breaker inside a conditional path.
    asm_code = (
        "mov rdx, 0x999;"       # The root input value
        "cmp rdx, 0x999;"       # The check that sets flags
        "je secret_path;"       # The conditional branch
        
        "mov rbx, 0x111;"       # Alternate path
        "jmp end;"
        
        "secret_path:"
        "xor rbx, rbx;"         # TAINT BREAKER! Data Flow ends here.
        
        "end:"
        "cmp rbx, 0;"           # Tracker trigger point
        "je very_end;"
        "very_end:"
        "nop;"
    )
    
    shellcode = compile_shellcode(asm_code)
    
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
