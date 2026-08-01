import sys
import os

# Ensure the app directories are in path
app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)
import speakeasy
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant
from asm_analyzer.engine.translator import Z3Translator
import z3

tracker = Tracker()
tick_counter = 0
current_mem_reads = []
current_mem_writes = []
module_base = 0
module_size = 0

def hook_mem_read(emu, access, address, size, value):
    current_mem_reads.append(address)

def hook_mem_write(emu, access, address, size, value):
    current_mem_writes.append(address)

def hook_code(se, address, size):
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


def run_speakeasy():
    global module_base, module_size
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    import speakeasy.config as cfg
    import copy
    custom_config = copy.deepcopy(cfg.DEFAULT_CONFIG_DATA)
    # We pass no arguments here, the input is hardcoded in crackme_boss.c's get_input()
    custom_config["command_line"] = "crackme_boss.exe"
    custom_config.setdefault("modules", {})["functions_always_exist"] = True
    
    se = speakeasy.Speakeasy(config=custom_config)
    
    print(f"[+] Loading {target_exe}...")
    module = se.load_module(target_exe)
    module_base = module.base
    module_size = module.image_size
    print(f"[+] Module loaded at 0x{module_base:x} (Size: 0x{module_size:x})")
    
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

    if tracker.trace_history:
        target_tick = -1
        # Track eax at the password check (cmp eax, 0xd80)
        for record in reversed(tracker.trace_history):
            if record.mnemonic == "cmp" and "0xde1770ef" in record.op_str.lower():
                target_tick = record.tick
                break
            
        if target_tick != -1:
            print(f"[!] Target Found at Tick {target_tick}!")
            desc = Descendant(target="eax", at_tick=target_tick)
            slice_records = tracker.build_backward_slice(desc)
            print("\n[+] ===========================================")
            print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
            for record in slice_records:
                print(f"    Tick {record.tick:04d}: {record.mnemonic} {record.op_str}")
            print("[+] ===========================================")
            
            # Integrate Z3 Translator
            print("\n[+] Passing Slice to Z3 Translator...")
            translator = Z3Translator()
            
            # Keep instructions up to atoi
            start_idx = 0
            for i, record in enumerate(slice_records):
                if record.address == 0x1400017ad:
                    start_idx = i
                    break
                    
            symbolic_slice = slice_records[:start_idx + 1]
            print(f"[+] Truncated Slice to {len(symbolic_slice)} instructions (ended at backward index {start_idx})")

            translator.translate_slice(symbolic_slice)
            
            # Add constraint: rax == 0xDE1770EF
            # Since check_key compares the final read memory with 0xDE1770EF
            rax_final = translator.reg_state.get('rax', None)
            if rax_final is not None:
                print("[+] Adding Goal Constraint: rax == 0xDE1770EF")
                translator.solver.add(rax_final == 0xDE1770EF)
            
            print("\n[*] Z3 Solving...")
            if translator.solver.check() == z3.sat:
                model = translator.solver.model()
                print(f"\n[SUCCESS] Z3 SOLVED THE BOSS FIGHT!")
                for d in model.decls():
                    val = model[d]
                    if z3.is_bv_value(val):
                        print(f"[SUCCESS] {d.name()} = {val.as_long() & 0xFFFFFFFF}")
                    else:
                        print(f"[SUCCESS] {d.name()} = {val}")
            else:
                print("\n[!] Z3 returned UNSAT. No solution found!")
        else:
            print("[-] Target not found! Did the binary exit early due to missing argc?")
            # Let's print the last 10 instructions to see where it stopped
            for r in tracker.trace_history[-10:]:
                print(f"    Tick {r.tick:04d}: {r.mnemonic} {r.op_str}")

if __name__ == "__main__":
    run_speakeasy()
