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
    print("[*] AsmAnalyzer - Temporal Memory PoC")
    
    # 1. We write a value to a register, move it to memory, read it into another register, then compare
    asm_code = (
        "mov rax, 0x1337;"    # Target value origin
        "mov r8, 0x10000;"    # Arbitrary memory address pointer
        "mov [r8], rax;"      # Write to memory (Temporal Memory saved)
        "mov rax, 0;"         # Clear RAX (Taint breaker for RAX)
        "mov rbx, [r8];"      # Read from memory into RBX
        "cmp rbx, 0x1337;"    # CONDITION: We track RBX backwards
        "je end;"
        "nop;"
        "end:"
        "nop;"
    )
    
    shellcode = compile_shellcode(asm_code)
    
    # We use a base address and map memory for our pointer
    core = AnalyzerCore(
        code=shellcode,
        rootfs=".",
        arch="x8664",
        os_type="windows"
    )
    
    # Map memory at 0x10000 for our test (Qiling needs memory to be mapped to write to it)
    core.ql.mem.map(0x10000, 0x1000)
    
    setup_hooks(core)
    core.start()

if __name__ == "__main__":
    main()
