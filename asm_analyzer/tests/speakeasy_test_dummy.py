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
module_base = 0
module_size = 0

def hook_mem_read(emu, access, address, size, value, user_data):
    current_mem_reads.append(address)

def hook_mem_write(emu, access, address, size, value, user_data):
    current_mem_writes.append(address)

def hook_code(se, address, size, user_data):
    global tick_counter, current_mem_reads, current_mem_writes
    
    # Filter only our target module!
    if not (module_base <= address < module_base + module_size):
        return
        
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    try:
        mem = se.mem_read(address, size)
    except:
        return
        
    if len(tracker.trace_history) > 0:
        tracker.trace_history[-1].mem_read.extend(current_mem_reads)
        tracker.trace_history[-1].mem_write.extend(current_mem_writes)
        
    current_mem_reads.clear()
    current_mem_writes.clear()
        
    for instr in md.disasm(mem, address):
        tick_counter += 1
        record = TraceRecord(tick_counter, address, instr.mnemonic, instr.op_str)
        
        regs_read, regs_write = instr.regs_access()
        record.regs_read = [instr.reg_name(r) for r in regs_read]
        record.regs_write = [instr.reg_name(r) for r in regs_write]
        
        tracker.add_trace(record)

def hook_api(emu, api_name, func, args):
    # Dummy hook to bypass unsupported APIs
    return 0

def run_speakeasy():
    global module_base, module_size
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    print("[+] Starting Speakeasy Emulator...")
    # Load default config and apply custom overlay
    import json
    config_path = os.path.join(os.path.dirname(speakeasy.__file__), 'configs', 'default.json')
    with open(config_path, 'r') as f:
        custom_config = json.load(f)
    
    custom_config["command_line"] = "crackme_boss.exe 300"
    custom_config.setdefault("modules", {})["functions_always_exist"] = True
    
    se = speakeasy.Speakeasy(config=custom_config)
    
    print(f"[+] Loading {target_exe}...")
    module = se.load_module(target_exe)
    module_base = module.get_base()
    module_size = module.get_image_size()
    print(f"[+] Module loaded at 0x{module_base:x} (Size: 0x{module_size:x})")
    
    # Set up our hooks
    se.add_code_hook(hook_code)
    se.add_mem_read_hook(hook_mem_read)
    se.add_mem_write_hook(hook_mem_write)



    print("[+] Emulating...")
    try:
        se.run_module(module)
    except Exception as e:
        print(f"[-] Emulation stopped: {e}")
        
    print(f"[+] Emulation finished! Traced {tick_counter} instructions from main binary.")
    
    # Flush last memory access
    if len(tracker.trace_history) > 0:
        tracker.trace_history[-1].mem_read.extend(current_mem_reads)
        tracker.trace_history[-1].mem_write.extend(current_mem_writes)

    # Search for cmp ecx, 3456
    print("\n[+] Searching trace for the target condition: cmp ecx, 3456")
    target_tick = -1
    for record in reversed(tracker.trace_history):
        if record.mnemonic == "cmp" and ("3456" in record.op_str or "0xd80" in record.op_str):
            target_tick = record.tick
            break
            
    if target_tick != -1:
        print(f"[!] Target Found at Tick {target_tick}!")
        desc = Descendant(target="ecx", at_tick=target_tick)
        slice_records = tracker.build_backward_slice(desc)
        print("\n[+] ===========================================")
        print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
        print("[+] ===========================================")
    else:
        print("[-] Target not found! Did the binary exit early due to missing argc?")
        # Let me print the last 30 instructions to see where it stopped
        for r in tracker.trace_history[-30:]:
            print(f"    Tick {r.tick:04d}: 0x{r.address:x} | {r.mnemonic} {r.op_str}")

    # Dump the trace to a file for inspection
    with open("trace.txt", "w") as f:
        for r in tracker.trace_history:
            f.write(f"Tick {r.tick:04d}: 0x{r.address:x} | {r.mnemonic} {r.op_str}\n")
    print("[+] Trace dumped to trace.txt")

if __name__ == "__main__":
    run_speakeasy()
