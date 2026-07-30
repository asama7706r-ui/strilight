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
    print("[*] AsmAnalyzer - Implicit Data Flow (Context-to-Physical-Interval) PoC")
    
    # Simulate calculating an address and jumping to it
    asm_code = (
        "mov rbx, 0x140000010;"  # Base address of our text segment (dummy)
        "mov rax, rbx;"
        "add rax, 0x5;"          # Math operation to find the jump target
        "jmp rax;"               # IMPLICIT DATA FLOW! The target is used to jump.
        "nop;"                   
        "nop;"                   
        "mov rdx, 1;"            # 0x140000015 (Jump target lands here)
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
    
    # Now, let's manually trigger a backward slice from the jump instruction
    # We want to know: "Why did we jump to RAX?" So we track RAX at Tick 4.
    from asm_analyzer.engine.tracker import Descendant
    desc = Descendant('rax', 4)
    print("\n[*] Manual Slicing Trigger: Tracking RAX backwards from the JMP instruction...")
    slice_res = core.tracker.build_backward_slice(desc)
    
    print("\n  [+] Backward Slice Result:")
    for s in reversed(slice_res):
        print(f"      - {s}")

if __name__ == "__main__":
    main()
