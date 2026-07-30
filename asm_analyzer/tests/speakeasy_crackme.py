import sys
import os

# Ensure the app directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import speakeasy
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant
from asm_analyzer.engine.translator import Z3Translator
import z3

# Global variables for tracing
tracker = Tracker()
tick_counter = 0
current_mem_reads = []
current_mem_writes = []

def hook_code(se, address, size, user_data):
    global tick_counter, current_mem_reads, current_mem_writes
    
    # We only care about instructions inside the main binary (not DLLs)
    # The module is loaded at an arbitrary base, we can check if address belongs to our module.
    # We will let Capstone disassemble it.
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    try:
        mem = se.mem_read(address, size)
    except:
        return
        
    for instr in md.disasm(mem, address):
        print(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")

def run_speakeasy():
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    print("[+] Starting Speakeasy Emulator...")
    se = speakeasy.Speakeasy()
    
    print(f"[+] Loading {target_exe}...")
    module = se.load_module(target_exe)
    
    # Set up our code hook
    se.add_code_hook(hook_code)
    
    print("[+] Emulating...")
    try:
        # Pass argv to the executable. Speakeasy usually takes arguments or command_line via the module/system config.
        # But wait, run_module doesn't take 'args' directly in older versions?
        # Actually, let's just try running it first. 
        se.run_module(module, all_entrypoints=True)
    except Exception as e:
        print(f"[-] Emulation stopped: {e}")
        
    print("[+] Emulation finished!")

if __name__ == "__main__":
    run_speakeasy()
