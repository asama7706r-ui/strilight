from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_MEM_WRITE, UC_MEM_READ
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant
from asm_analyzer.engine.translator import Z3Translator
import z3

# 1. The "Boss Fight" logic written in Assembly
# This perfectly mimics the C code but removes the OS/CRT overhead.
asm_code = b"""
    mov eax, 300
    
    xor eax, 0x5a
    imul eax, eax, 3
    
    cmp eax, 1000
    jl fail1
    
    mov ebx, 0x5000
    mov dword ptr [ebx], eax
    
    add eax, 5
    
    mov ecx, dword ptr [ebx]
    cmp ecx, 3456
    je success
    
fail1:
    mov r8, 0
    jmp end
success:
    mov r8, 1
end:
    nop
"""

# 2. Compile Assembly to Shellcode
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(asm_code)
code_bytes = bytes(encoding)

# 3. Setup Unicorn Emulator
ADDRESS = 0x1000000
HEAP_ADDR = 0x5000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(ADDRESS, 2 * 1024 * 1024)
mu.mem_map(0x0, 2 * 1024 * 1024) # map lower memory for heap 0x5000
mu.mem_write(ADDRESS, code_bytes)

# Set initial registers to 0 to avoid garbage
mu.reg_write(UC_X86_REG_RAX, 0)
mu.reg_write(UC_X86_REG_RBX, 0)
mu.reg_write(UC_X86_REG_RCX, 0)
mu.reg_write(UC_X86_REG_R8, 0)

# Setup Tracker and Capstone
tracker = Tracker()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

tick_counter = 0
current_mem_reads = []
current_mem_writes = []

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_MEM_WRITE, UC_MEM_READ

def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        current_mem_writes.append(address)
    else:
        current_mem_reads.append(address)

def hook_code(uc, address, size, user_data):
    global tick_counter, current_mem_reads, current_mem_writes
    
    if len(tracker.trace_history) > 0:
        tracker.trace_history[-1].mem_read.extend(current_mem_reads)
        tracker.trace_history[-1].mem_write.extend(current_mem_writes)
        
    current_mem_reads.clear()
    current_mem_writes.clear()
    
    buf = uc.mem_read(address, size)
    for insn in md.disasm(buf, address):
        tick_counter += 1
        record = TraceRecord(tick_counter, address, insn.mnemonic, insn.op_str)
        
        regs_read, regs_write = insn.regs_access()
        record.regs_read = [insn.reg_name(r) for r in regs_read]
        record.regs_write = [insn.reg_name(r) for r in regs_write]
        
        tracker.add_trace(record)

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_mem_access)

print("[+] Starting Unicorn Engine Execution...")
try:
    mu.emu_start(ADDRESS, ADDRESS + len(code_bytes))
except Exception as e:
    print(f"[-] Emulator Error: {e}")

# Flush last memory access
if len(tracker.trace_history) > 0:
    tracker.trace_history[-1].mem_read.extend(current_mem_reads)
    tracker.trace_history[-1].mem_write.extend(current_mem_writes)

print(f"[+] Trace Complete! Total instructions executed: {tick_counter}")
if mu.reg_read(UC_X86_REG_R8) == 1:
    print("    Result: SUCCESS path taken.")
else:
    print("    Result: FAIL path taken.")

# 4. Automate Tracker
print("\n[+] Searching trace for the target condition: cmp ecx, 3456")
target_tick = -1
for record in reversed(tracker.trace_history):
    if record.mnemonic == "cmp" and ("3456" in record.op_str or "0xd80" in record.op_str):
        target_tick = record.tick
        break

if target_tick != -1:
    print(f"[!] Target Found at Tick {target_tick}!")
    # Track the register being compared (ecx)
    desc = Descendant(target="ecx", at_tick=target_tick)
    print(f"[+] Launching Tracker for 'ecx' backwards from Tick {target_tick}...")
    
    slice_records = tracker.build_backward_slice(desc)
    
    print("\n[+] ===========================================")
    print(f"[+] Final Slice Extracted ({len(slice_records)} instructions):")
    for r in slice_records:
        print(f"    Tick {r.tick:04d}: {r.mnemonic} {r.op_str}")
    print("[+] ===========================================")
    
    # --- 5. Symbolic Execution with Z3 ---
    print("\n[+] Passing Slice to Z3 Translator...")
    
    # We want Z3 to SOLVE for the input. The dummy input was provided at Tick 1: mov eax, 0x12c
    # If we feed Tick 1 to Z3, it will think the input MUST be 0x12c.
    # So we remove Tick 1 to make 'eax' a free symbolic variable!
    symbolic_slice = [r for r in slice_records if r.tick != 1]
    
    translator = Z3Translator()
    
    # In translator, conditional jumps (like jl) need to be explicitly constrained based on the PathTree.
    # For now, we will add the constraints manually for the Boss Fight:
    translator.translate_slice(symbolic_slice)
    
    # Add path constraint for Tick 5: 'jl fail' was NOT taken in our success path.
    # 'jl' is taken if SF != OF. Since it was NOT taken, SF == OF.
    flag_sf = translator.flag_state.get('flag_sf')
    flag_of = translator.flag_state.get('flag_of')
    if flag_sf is not None and flag_of is not None:
        print("[+] Adding Path Constraint: jl was NOT taken (SF == OF)")
        translator.solver.add(flag_sf == flag_of)
    
    # Add final goal constraint: ecx == 3456
    ecx_final = translator.reg_state['rcx']
    print("[+] Adding Goal Constraint: rcx == 3456")
    translator.solver.add(ecx_final == 3456)
    
    print("\n[*] Z3 Solving...")
    if translator.solver.check() == z3.sat:
        model = translator.solver.model()
        
        # The free variable 'eax_0' represents the initial input (before xor)
        # We need to find the earliest 'eax' in the model
        for d in model.decls():
            if 'rax' in d.name() and '_0' in d.name():
                solution = model[d].as_long()
                # Apply 32-bit mask to ignore upper garbage bits
                solution = solution & 0xFFFFFFFF
                print(f"\n[SUCCESS] Z3 SOLVED THE BOSS FIGHT!")
                print(f"[SUCCESS] The correct user_key is: {solution}")
                break
    else:
        print("\n[!] Z3 returned UNSAT. No solution found!")

else:
    print("[-] Target not found!")
