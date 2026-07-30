import os
import sys

# Ensure the root of the project is in sys.path so we can import asm_analyzer
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def compile_shellcode(assembly: str) -> bytes:
    """Compiles x86-64 assembly to raw bytes using Keystone."""
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(assembly)
    return bytes(encoding)

def main():
    print("[*] AsmAnalyzer - Basic PoC (Proof of Concept)")
    
    # 1. Prepare a simple dummy shellcode to test hooks
    # This shellcode increments a register and does a simple comparison
    asm_code = (
        "mov rax, 0;"         # Tick 1
        "add rax, 10;"        # Tick 2
        "cmp rax, 10;"        # Tick 3 (Modifies EFLAGS)
        "je end;"             # Tick 4 (Conditional jump based on EFLAGS)
        "mov rbx, 0x99;"      # Should be skipped
        "end:"
        "nop;"                # Tick 5
    )
    
    print("[*] Compiling dummy shellcode...")
    shellcode = compile_shellcode(asm_code)
    
    # 2. Initialize Analyzer Core
    print("[*] Initializing Analyzer Core...")
    core = AnalyzerCore(
        code=shellcode,
        rootfs=".",
        arch="x8664",
        os_type="windows"
    )
    
    # 3. Setup tracking and interception hooks
    setup_hooks(core)
    
    # 4. Start Emulation
    core.start()

if __name__ == "__main__":
    main()
