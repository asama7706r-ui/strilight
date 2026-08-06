import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.stop_dict import STOP_FUNCTIONS

# Initialize capstone for disassembling intercepted instructions
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True  # Enable detailed mode to get read/write registers

def setup_hooks(core_instance):
    """
    Register all hooks with the Speakeasy instance.
    """
    se = core_instance.se

    def hook_code(emu, address, size):
        # Only trace the main binary module, ignore emulator internals
        if not (core_instance.module_base <= address < core_instance.module_base + core_instance.module_size):
            return
            
        core_instance.tick_counter += 1
        
        try:
            buf = emu.mem_read(address, size)
        except Exception:
            return
            
        # Append buffered memory accesses to the PREVIOUS instruction
        if len(core_instance.tracker.trace_history) > 0:
            core_instance.tracker.trace_history[-1].mem_read.extend(core_instance.current_mem_reads)
            core_instance.tracker.trace_history[-1].mem_write.extend(core_instance.current_mem_writes)
            
        core_instance.current_mem_reads.clear()
        core_instance.current_mem_writes.clear()
        
        for i in md.disasm(buf, address):
            record = TraceRecord(core_instance.tick_counter, address, i.size, i.mnemonic, i.op_str)
            
            reads = []
            writes = []
            
            # Implicit registers
            if i.regs_read:
                reads.extend([i.reg_name(r) for r in i.regs_read])
            if i.regs_write:
                writes.extend([i.reg_name(r) for r in i.regs_write])
                
            ops_structs = []
            # Explicit operands
            if i.operands:
                for idx, op in enumerate(i.operands):
                    if op.type == X86_OP_REG:
                        reg_name = i.reg_name(op.reg)
                        ops_structs.append({'type': 'reg', 'value': reg_name, 'size': op.size})
                        if idx == 0 and i.mnemonic not in ('cmp', 'test'):
                            if i.mnemonic not in ('mov', 'lea'):
                                reads.append(reg_name)
                            writes.append(reg_name)
                        else:
                            reads.append(reg_name)
                            
                    elif op.type == X86_OP_MEM:
                        base = i.reg_name(op.mem.base) if op.mem.base != 0 else None
                        index = i.reg_name(op.mem.index) if op.mem.index != 0 else None
                        ops_structs.append({
                            'type': 'mem',
                            'base': base,
                            'index': index,
                            'scale': op.mem.scale,
                            'disp': op.mem.disp,
                            'size': op.size
                        })
                        if op.mem.base != 0:
                            reads.append(base)
                        if op.mem.index != 0:
                            reads.append(index)
                    elif op.type == X86_OP_IMM:
                        ops_structs.append({'type': 'imm', 'value': op.imm, 'size': op.size})

            record.operands = ops_structs

            record.regs_read = list(set(reads))
            record.regs_write = list(set(writes))
            
            core_instance.tracker.add_trace(record)
            
            # Optional: Log the instruction for debugging
            # print(f"[Tick: {core_instance.tick_counter:04d}] 0x{address:x}: {i.mnemonic} {i.op_str}")
            
            # NOTE: Removed dynamic backward slicing on every CMP to avoid extreme performance overhead.
            # Backward slicing should be triggered selectively after emulation finishes or on a specific target.

    def hook_mem_read(emu, access, address, size, value):
        core_instance.current_mem_reads.append(address)

    def hook_mem_write(emu, access, address, size, value):
        core_instance.current_mem_writes.append(address)

    # Register API Hooks based on STOP_FUNCTIONS
    def create_api_hook(api_name, api_type):
        def api_hook_callback(emu, hook_api_name, func, params):
            print(f"[*] API Hook Triggered: {hook_api_name} (Type: {api_type}) at Tick {core_instance.tick_counter}")
            
            # 1. Allow the native Speakeasy mock to execute
            rv = func(params)
            
            # 2. Mark the previous instruction as a Taint Breaker
            if len(core_instance.tracker.trace_history) > 0:
                record = core_instance.tracker.trace_history[-1]
                # Simulating a Taint Break on RAX and volatile registers (standard x64 calling convention)
                record.regs_write.extend(['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'])
                record.regs_write = list(set(record.regs_write))
                print(f"  -> [Taint Breaker] Applied API boundary to {hook_api_name} at Tick {record.tick}")
                
            # 3. Stop Point check
            if api_type == "input" or api_type == "network_input":
                print(f"  -> [Stop Point] Interactive API {hook_api_name} detected. Stopping emulation!")
                emu.stop()
                
            return rv
            
        return api_hook_callback

    # Register the stop functions as API hooks across all modules ("*")
    for func_name, func_type in STOP_FUNCTIONS.items():
        se.add_api_hook(create_api_hook(func_name, func_type), "*", func_name)

    # Add code and memory hooks
    se.add_code_hook(hook_code)
    se.add_mem_read_hook(hook_mem_read)
    se.add_mem_write_hook(hook_mem_write)
    
    print("[+] Hooks initialized successfully with Speakeasy API Classifier.")
