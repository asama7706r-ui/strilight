import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.path_tree import PathTree
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def compile_shellcode(assembly: str) -> bytes:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(assembly)
    return bytes(encoding)

def main():
    print("[*] AsmAnalyzer - Dead-End Logging PoC")
    
    asm_code = "nop; nop; nop;"
    shellcode = compile_shellcode(asm_code)
    
    core = AnalyzerCore(
        code=shellcode,
        rootfs=".",
        arch="x8664",
        os_type="windows"
    )
    
    setup_hooks(core)
    
    # 1. Start execution to map memory
    core.start()
    
    # 2. Grab memory hash BEFORE changing permissions
    hash_state_1 = core.get_memory_permissions_hash()
    print(f"\n[+] Memory Permissions Hash (State 1): {hash_state_1}")
    
    # 3. Simulate a crash and log a Dead-End
    # Let's say tracing RAX at Tick 2 caused a crash because memory was NX.
    core.tracker.path_tree.mark_dead_end('rax', 2, hash_state_1, "Access Violation (NX)")
    
    # 4. Check if it's blocked
    is_blocked_1 = core.tracker.path_tree.is_dead_end('rax', 2, hash_state_1)
    print(f"[*] Checking Path (RAX, Tick 2, State 1). Is Dead End? {is_blocked_1}")
    
    # 5. Now, pretend the program executed a VirtualProtect that made the page Executable (X).
    # We simulate this by changing memory protections in Qiling
    print("\n[!] Simulating VirtualProtect... Changing memory protection...")
    # Change protection of the text segment to RWX
    core.ql.mem.protect(0x140000000, 0x1000, 7) # 7 = RWX
    
    # 6. Grab memory hash AFTER changing permissions
    hash_state_2 = core.get_memory_permissions_hash()
    print(f"[+] Memory Permissions Hash (State 2): {hash_state_2}")
    
    # 7. Check if it's blocked now
    is_blocked_2 = core.tracker.path_tree.is_dead_end('rax', 2, hash_state_2)
    print(f"[*] Checking Path (RAX, Tick 2, State 2). Is Dead End? {is_blocked_2}")
    
    if is_blocked_1 and not is_blocked_2:
        print("\n[+] SUCCESS! The Dead-End cache is Context-Aware. It recognized the changed memory permissions and allowed the path!")

if __name__ == "__main__":
    main()
