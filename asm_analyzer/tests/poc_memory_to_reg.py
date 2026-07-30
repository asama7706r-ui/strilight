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
    print("[*] AsmAnalyzer - Memory to Register Propagation PoC")
    
    asm_code = (
        "mov rdx, 0x555;"        # The original seed
        "mov rax, rdx;"          # Seed moves to RAX
        "mov rbx, rsp;"          # Use stack address
        "sub rbx, 8;"
        "mov [rbx], rax;"        # Value is written to Memory
        "mov rcx, [rbx];"        # Value is read from Memory into RCX
        "add rcx, 1;"            # Operations on RCX
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
    
    # Track RCX backwards
    from asm_analyzer.engine.tracker import Descendant
    desc = Descendant('rcx', 6)
    print(f"\n[*] Manual Slicing Trigger: Tracking 'rcx' backwards from Tick 6...")
    slice_res = core.tracker.build_backward_slice(desc)
    
    print("\n  [+] Backward Slice Result:")
    for s in reversed(slice_res):
        print(f"      - {s}")

if __name__ == "__main__":
    main()
