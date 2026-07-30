import sys
import os

# Ensure the app directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from asm_analyzer.engine.tracker import Tracker, TraceRecord, Descendant
from asm_analyzer.engine.translator import Z3Translator

# Global variables for tracing
tracker = Tracker()
tick_counter = 0
current_mem_reads = []
current_mem_writes = []
md = None

is_tracking = False

def hook_mem_read(ql, access, address, size, value):
    global current_mem_reads, is_tracking
    if is_tracking:
        current_mem_reads.append(address)

def hook_mem_write(ql, access, address, size, value):
    global current_mem_writes, is_tracking
    if is_tracking:
        current_mem_writes.append(address)

def hook_code(ql, address, size):
    global tick_counter, current_mem_reads, current_mem_writes, md, tracker, is_tracking
    
    # Attach memory accesses to the PREVIOUS instruction
    if len(tracker.trace_history) > 0 and (current_mem_reads or current_mem_writes):
        last_record = tracker.trace_history[-1]
        last_record.mem_read.extend(current_mem_reads)
        last_record.mem_write.extend(current_mem_writes)
        
    current_mem_reads.clear()
    current_mem_writes.clear()
    
    is_tracking = (0x140000000 <= address <= 0x140100000)
    if not is_tracking:
        return
        
    # We patched library calls to NOPs, so we just set the return registers when we hit them
    if address == 0x1400017a8:  # call atoi
        ql.arch.regs.rax = 300
    elif address == 0x1400017e5:  # call malloc
        ql.arch.regs.rax = 0x3000000
        
    try:
        buf = ql.mem.read(address, size)
        for insn in md.disasm(buf, address):
            tick_counter += 1
            record = TraceRecord(tick_counter, address, insn.mnemonic, insn.op_str)
            
            regs_read, regs_write = insn.regs_access()
            record.regs_read = [insn.reg_name(r) for r in regs_read]
            record.regs_write = [insn.reg_name(r) for r in regs_write]
            
            tracker.add_trace(record)
    except Exception as e:
        pass

def on_entry(ql):
    print("[+] Reached entry point, installing hooks...")
    ql.hook_code(hook_code)
    ql.hook_mem_read(hook_mem_read)
    ql.hook_mem_write(hook_mem_write)

def run_crackme():
    global md
    
    target_exe = r"D:\work_app\MyApp\qiling_rootfs\x8664_windows\bin\crackme_boss.exe"
    args = [target_exe, "300"]
    
    print("[+] Starting Qiling Emulator...")
    rootfs_path = r"D:\work_app\MyApp\qiling_rootfs\x8664_windows"
    ql = Qiling(args, rootfs=rootfs_path)
    
    if ql.arch.bits == 64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        
    md.detail = True
    
    # --- Clean CRT Initialization via API Stubs (No Memory Patching) ---
    
    def hook_initterm(ql, address, params):
        return 0

    def hook_configure_narrow(ql, address, params):
        return 0

    def hook_get_argc(ql, address, params):
        return 2

    def hook_get_argv(ql, address, params):
        argv1_addr = 0x2000000
        try:
            ql.mem.map(argv1_addr, 0x1000)
        except:
            pass
        ql.mem.write(argv1_addr, b"300\x00")
        argv_array_addr = 0x2000100
        try:
            ql.mem.map(argv_array_addr, 0x1000)
        except:
            pass
        ql.mem.write(argv_array_addr, b"\x00"*8 + argv1_addr.to_bytes(8, 'little'))
        return argv_array_addr

    def hook_malloc(ql, address, params):
        size = params.get('dwSize', 0x1000) if isinstance(params, dict) else 0x1000
        heap_addr = 0x3000000
        try:
            ql.mem.map(heap_addr, 0x1000)
        except:
            pass
        return heap_addr

    def hook_atoi(ql, address, params):
        return 300

    def hook_puts(ql, address, params):
        return 0

    def hook_free(ql, address, params):
        return 0

    # Register API stubs for CRT init and libc functions
    for func in ['_initterm', '_initterm_e', '_configure_narrow_argv', '_initialize_narrow_environment', '_set_app_type', '_set_invalid_parameter_handler', '_configthreadlocale', '__setusermatherr', '_set_new_mode', '__acrt_iob_func', '__p__commode', '__p__fmode', '__stdio_common_vfprintf', '_cexit', '_exit']:
        ql.os.set_api(func, hook_initterm)

    ql.os.set_api('__p___argc', hook_get_argc)
    ql.os.set_api('__p___argv', hook_get_argv)
    ql.os.set_api('malloc', hook_malloc)
    ql.os.set_api('atoi', hook_atoi)
    ql.os.set_api('puts', hook_puts)
    ql.os.set_api('free', hook_free)

    # Hook the entry point to start tracing cleanly
    def on_entry(ql):
        print("[+] CRT Initialization Completed Cleanly! Installing tracing hooks.", flush=True)
        ql.hook_code(hook_code)
        ql.hook_mem_read(hook_mem_read)
        ql.hook_mem_write(hook_mem_write)

    ql.hook_address(on_entry, 0x14000105f)
    
    try:
        ql.run()
    except Exception as e:
        print(f"[-] Execution ended or errored: {e}")
        
    if len(tracker.trace_history) > 0:
        tracker.trace_history[-1].mem_read.extend(current_mem_reads)
        tracker.trace_history[-1].mem_write.extend(current_mem_writes)

    print(f"\n[+] Trace Completed. Total Ticks: {tick_counter}")
    
    print("\n[+] Last 10 instructions executed:")
    for record in tracker.trace_history[-10:]:
        print(f"    {hex(record.address)}: {record.mnemonic} {record.op_str}")
    
    target_tick = -1
    target_operand = ""
    
    for record in reversed(tracker.trace_history):
        if record.mnemonic == "cmp" and ("0xd80" in record.op_str or "3456" in record.op_str):
            target_tick = record.tick
            target_operand = record.op_str.split(",")[0].strip()
            print(f"[!] Found Target Condition at Tick {target_tick}: {record.mnemonic} {record.op_str}")
            break
            
    if target_tick != -1:
        print(f"\n[+] Initiating Backward Slicer from Tick {target_tick} for target '{target_operand}'...")
        target_record = tracker.get_trace_at_tick(target_tick)
        
        if target_record.mem_read:
            target_addr = target_record.mem_read[0]
            print(f"    Target is Memory Address: 0x{target_addr:x}")
            desc = Descendant(target=target_addr, at_tick=target_tick, is_memory=True)
        else:
            target_reg = target_record.regs_read[0]
            print(f"    Target is Register: {target_reg}")
            desc = Descendant(target=target_reg, at_tick=target_tick)
            
        slice_records = tracker.build_backward_slice(desc)
        print(f"\n[+] Slice Built. Total Instructions in Slice: {len(slice_records)}")
        
        print("\n[+] Handing over to Z3 Translator...")
        translator = Z3Translator()
        translator.translate_slice(slice_records)
        
        import z3
        
        # We need to explicitly constrain the target operand to match the comparison value.
        # target_operand is 'eax', and the target value from cmp is 0xd80.
        if target_operand in translator.reg_state:
            target_expr = translator.reg_state[target_operand]
            target_val = 0xd80
            translator.solver.add(target_expr == target_val)
            print(f"[+] Added constraint: {target_operand} == {hex(target_val)}")
        else:
            print(f"[-] {target_operand} not found in reg_state!")
        
        res = translator.solver.check()
        print("[+] Z3 Solver Result:", res)
        
        if res == z3.sat:
            m = translator.solver.model()
            print("[+] Z3 Model:", m)
            
            # Extract the flag/input from argv[1]
            # argv[1] is located at 0x2000000 in memory (Mem_rax_0 is the first memory read for argv)
            for d in m.decls():
                if "Mem_" in d.name() and m[d] is not None:
                    val = m[d].as_long()
                    print(f"    Possible Input (from {d.name()}): {val} -> {val.to_bytes((val.bit_length() + 7) // 8 or 1, 'little')}")
        else:
            print("[-] Z3 could not find a solution (unsat).")
    else:
        print("[-] Could not find the final 'cmp' instruction in the trace.")

if __name__ == "__main__":
    run_crackme()
