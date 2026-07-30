# pyrefly: ignore [missing-import]
from qiling import Qiling
# pyrefly: ignore [missing-import]
from qiling.const import QL_INTERCEPT
import capstone
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

from asm_analyzer.engine.tracker import TraceRecord

# Initialize capstone for disassembling intercepted instructions
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True  # Enable detailed mode to get read/write registers

def hook_code(ql: Qiling, address: int, size: int, core_instance):
    """
    Hook executed before every instruction.
    :param ql: Qiling instance
    :param address: Instruction address
    :param size: Instruction size
    :param core_instance: Reference to the AnalyzerCore instance
    """
    # Increment the central tick counter
    core_instance.tick_counter += 1
    
    # Read the instruction bytes
    buf = ql.mem.read(address, size)
    
    # Disassemble the instruction (for logging/analysis)
    for i in md.disasm(buf, address):
        record = TraceRecord(core_instance.tick_counter, address, i.mnemonic, i.op_str)
        
        reads = []
        writes = []
        
        # Implicit registers
        if i.regs_read:
            reads.extend([i.reg_name(r) for r in i.regs_read])
        if i.regs_write:
            writes.extend([i.reg_name(r) for r in i.regs_write])
            
        # Explicit operands
        # In x86, typically operand 0 is destination (written), operand 1 is source (read)
        # Exception: cmp, test reads both. 
        if i.operands:
            for idx, op in enumerate(i.operands):
                if op.type == X86_OP_REG:
                    reg_name = i.reg_name(op.reg)
                    # Simple heuristic: If it's the first operand and not a comparison/test, it's a write.
                    # Otherwise, it's a read.
                    if idx == 0 and i.mnemonic not in ('cmp', 'test'):
                        # If it's something like add rax, rbx -> rax is read AND written
                        if i.mnemonic not in ('mov', 'lea'):
                            reads.append(reg_name)
                        writes.append(reg_name)
                    else:
                        reads.append(reg_name)
                        
                elif op.type == X86_OP_MEM:
                    if op.mem.base != 0:
                        reads.append(i.reg_name(op.mem.base))
                    if op.mem.index != 0:
                        reads.append(i.reg_name(op.mem.index))

        record.regs_read = list(set(reads))
        record.regs_write = list(set(writes))
        
        # [TEMPORARY SOLUTION]: API Boundary Detection
        # As per the Architectural Document, a proper API Classifier is needed.
        # This is a temporary patch to treat 'call' instructions as Taint Breakers 
        # (especially external library calls that mock returns in rax without x86 execution).
        # We assume 'call' clobbers standard x64 volatile registers.
        if i.mnemonic == 'call':
            record.regs_write.extend(['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'])
            # Remove duplicates if any
            record.regs_write = list(set(record.regs_write))
            
        # Add to the tracker's history
        core_instance.tracker.add_trace(record)
        
        print(f"[Tick: {core_instance.tick_counter:04d}] 0x{address:x}: {i.mnemonic} {i.op_str} | Reads: {record.regs_read} | Writes: {record.regs_write}")
        
        # Trigger Backward Slicing if we hit a condition (e.g. CMP)
        if i.mnemonic == "cmp":
            from asm_analyzer.engine.tracker import Descendant
            # For demonstration, we'll assume the first operand is what we want to track
            target_reg = i.op_str.split(',')[0].strip()
            desc = Descendant(target_reg, core_instance.tick_counter)
            
            # First attempt: Will calculate and cache
            slice_res = core_instance.tracker.build_backward_slice(desc)
            print("  [+] Backward Slice Result:")
            for s in reversed(slice_res):
                print(f"      - {s}")
                
            # Second attempt: Should hit the PathTree Memoization Cache
            print(f"[*] Simulating a secondary intersection requesting the same slice for '{target_reg}' at Tick {core_instance.tick_counter}...")
            slice_res_cached = core_instance.tracker.build_backward_slice(desc)
            if slice_res_cached == slice_res:
                print("  [+] Cache hit successful and matches original slice!")

def hook_mem_read(ql: Qiling, access: int, address: int, size: int, value: int, core_instance):
    """
    Hook for memory read operations.
    """
    if core_instance.tracker.trace_history:
        record = core_instance.tracker.trace_history[-1]
        record.mem_read.append(address)
    #print(f"  [Mem READ ] 0x{address:x} (Size: {size}) -> Value: {value:x} at Tick: {core_instance.tick_counter}")

def hook_mem_write(ql: Qiling, access: int, address: int, size: int, value: int, core_instance):
    """
    Hook for memory write operations.
    """
    if core_instance.tracker.trace_history:
        record = core_instance.tracker.trace_history[-1]
        record.mem_write.append(address)
    #print(f"  [Mem WRITE] 0x{address:x} (Size: {size}) <- Value: {value:x} at Tick: {core_instance.tick_counter}")

def setup_hooks(core_instance):
    """
    Register all hooks with the Qiling instance.
    """
    ql = core_instance.ql
    
    # Hook every instruction
    ql.hook_code(hook_code, user_data=core_instance)
    
    # Hook memory reads and writes
    ql.hook_mem_read(hook_mem_read, user_data=core_instance)
    ql.hook_mem_write(hook_mem_write, user_data=core_instance)
    
    print("[+] Hooks initialized successfully.")
