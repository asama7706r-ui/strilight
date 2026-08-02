import sys
import os
import copy

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)

import speakeasy
import speakeasy.config as cfg
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
        record.size = instr.size
        regs_read, regs_write = instr.regs_access()
        record.regs_read = [instr.reg_name(r) for r in regs_read]
        record.regs_write = [instr.reg_name(r) for r in regs_write]
        tracker.add_trace(record)

def run_speakeasy():
    global module_base, module_size
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    custom_config = copy.deepcopy(cfg.DEFAULT_CONFIG_DATA)
    custom_config["command_line"] = "crackme_boss.exe 5001"
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
    
    if len(tracker.trace_history) > 0:
        tracker.trace_history[-1].mem_read.extend(current_mem_reads)
        tracker.trace_history[-1].mem_write.extend(current_mem_writes)

    if tracker.trace_history:
        target_tick = -1
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
            
            symbolic_slice = slice_records
            chronological_slice = list(reversed(symbolic_slice))
            
            # Truncate to check_key (last push rbp before target)
            start_idx = 0
            for i in range(len(chronological_slice) - 1, -1, -1):
                if chronological_slice[i].mnemonic == 'push' and 'rbp' in chronological_slice[i].op_str:
                    start_idx = i
                    break
            chronological_slice = chronological_slice[start_idx:]
            print(f"[+] Truncated chronological slice to {len(chronological_slice)} instructions")
            
            translator = Z3Translator()
            key_var = z3.BitVec("key_input", 32)
            injected = False
            
            for record in chronological_slice:
                if record.tick == target_tick + 1:
                    if record.jump_taken is not None:
                        record.jump_taken = not record.jump_taken
                        print(f"[!] Flipped target jump at Tick {record.tick} to force winning path!")
                        
                translator.parse_instruction(record)
                
                # Inject key at the start of check_key (first push rbp)
                if not injected and record.mnemonic == "push" and "rbp" in record.op_str:
                    translator.reg_state["ecx"] = key_var
                    translator.reg_state["rcx"] = z3.ZeroExt(32, key_var)
                    injected = True
                    print(f"[+] Injected symbolic key into ecx at Tick {record.tick}")
            
            rax_final = translator.reg_state.get("rax", None)
            if rax_final is not None:
                print("[+] Adding Goal Constraint: rax == 0xDE1770EF")
                translator.solver.add(rax_final == 0xDE1770EF)
            
            print("\n[*] Z3 Solving...")
            if translator.solver.check() == z3.sat:
                model = translator.solver.model()
                print(f"\n[SUCCESS] Z3 SOLVED THE BOSS FIGHT!")
                for d in model.decls():
                    print(f"[SUCCESS] {d.name()} = {model[d]}")
            else:
                print("\n[!] Z3 returned UNSAT. No solution found!")
        else:
            print("[-] Target not found!")
            
if __name__ == '__main__':
    run_speakeasy()
