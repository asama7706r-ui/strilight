from typing import List, Dict, Any, Optional

class TraceRecord:
    def __init__(self, tick: int, address: int, mnemonic: str, op_str: str, thread_id: int = 0):
        self.tick = tick
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.thread_id = thread_id
        
        # Details about what this instruction read or wrote
        self.regs_read: List[str] = []
        self.regs_write: List[str] = []
        self.mem_read: List[int] = []
        self.mem_write: List[int] = []
        self.requested_flags: List[str] = []  # For Lazy Flag Generation

    def __repr__(self):
        return f"<TraceRecord Tick:{self.tick:04d} {self.mnemonic} {self.op_str}>"

class Descendant:
    def __init__(self, target: str, at_tick: int, is_memory: bool = False):
        self.target = target        # Register name or memory address
        self.at_tick = at_tick      # The point in time it hit the condition
        self.is_memory = is_memory
        
        # The ancestors that contributed to this descendant
        self.ancestors: List['Ancestor'] = []

class Ancestor:
    def __init__(self, target: str, modified_at_tick: int, instruction: TraceRecord):
        self.target = target
        self.modified_at_tick = modified_at_tick
        self.instruction = instruction

class Tracker:
    MODIFIES_ALL_FLAGS = {"add", "sub", "cmp", "test", "and", "or", "xor", "shl", "shr"}
    MODIFIES_ZSO_ONLY = {"inc", "dec"}
    JUMP_FLAGS = {
        "je": ["flag_zf"], "jz": ["flag_zf"],
        "jne": ["flag_zf"], "jnz": ["flag_zf"],
        "ja": ["flag_cf", "flag_zf"], "jnbe": ["flag_cf", "flag_zf"],
        "jae": ["flag_cf"], "jnb": ["flag_cf"],
        "jb": ["flag_cf"], "jnae": ["flag_cf"], "jc": ["flag_cf"],
        "jbe": ["flag_cf", "flag_zf"], "jna": ["flag_cf", "flag_zf"],
        "jg": ["flag_zf", "flag_sf", "flag_of"], "jnle": ["flag_zf", "flag_sf", "flag_of"],
        "jge": ["flag_sf", "flag_of"], "jnl": ["flag_sf", "flag_of"],
        "jl": ["flag_sf", "flag_of"], "jnge": ["flag_sf", "flag_of"],
        "jle": ["flag_zf", "flag_sf", "flag_of"], "jng": ["flag_zf", "flag_sf", "flag_of"],
        "js": ["flag_sf"], "jns": ["flag_sf"],
        "jo": ["flag_of"], "jno": ["flag_of"]
    }

    REGISTER_SIZES = {
        "rax": 8, "rbx": 8, "rcx": 8, "rdx": 8, "rsi": 8, "rdi": 8, "rbp": 8, "rsp": 8,
        "r8": 8, "r9": 8, "r10": 8, "r11": 8, "r12": 8, "r13": 8, "r14": 8, "r15": 8,
        "eax": 4, "ebx": 4, "ecx": 4, "edx": 4, "esi": 4, "edi": 4, "ebp": 4, "esp": 4,
        "r8d": 4, "r9d": 4, "r10d": 4, "r11d": 4, "r12d": 4, "r13d": 4, "r14d": 4, "r15d": 4,
        "ax": 2, "bx": 2, "cx": 2, "dx": 2, "si": 2, "di": 2, "bp": 2, "sp": 2,
        "r8w": 2, "r9w": 2, "r10w": 2, "r11w": 2, "r12w": 2, "r13w": 2, "r14w": 2, "r15w": 2,
        "al": 1, "ah": 1, "bl": 1, "bh": 1, "cl": 1, "ch": 1, "dl": 1, "dh": 1,
        "sil": 1, "dil": 1, "bpl": 1, "spl": 1,
        "r8b": 1, "r9b": 1, "r10b": 1, "r11b": 1, "r12b": 1, "r13b": 1, "r14b": 1, "r15b": 1,
    }

    def _calculate_memory_write_size(self, record: TraceRecord) -> int:
        write_size = 1 # Default
        for reg in record.regs_read:
            if reg in self.REGISTER_SIZES:
                write_size = max(write_size, self.REGISTER_SIZES[reg])
                
        if write_size == 1:
            if "qword ptr" in record.op_str.lower(): write_size = 8
            elif "dword ptr" in record.op_str.lower(): write_size = 4
            elif "word ptr" in record.op_str.lower(): write_size = 2
        return write_size

    def __init__(self):
        self.trace_history: List[TraceRecord] = []
        from asm_analyzer.engine.path_tree import PathTree
        self.path_tree = PathTree()
    
    def add_trace(self, record: TraceRecord):
        """Append an executed instruction to the history."""
        self.trace_history.append(record)
        
    def get_trace_at_tick(self, tick: int) -> Optional[TraceRecord]:
        if 0 < tick <= len(self.trace_history):
            return self.trace_history[tick - 1]
        return None

    def build_backward_slice(self, initial_descendant: Descendant) -> List[TraceRecord]:
        """
        Walks backwards using an Iterative Worklist to prevent RecursionError on deeply nested
        control dependencies. Uses PathTree for Memoization.
        """
        worklist = [initial_descendant]
        all_slice_instructions = []
        
        while worklist:
            descendant = worklist.pop(0) # BFS
            
            # 1. Check PathTree Memoization Cache first
            cached_slice = self.path_tree.get_cached_slice(descendant.target, descendant.at_tick)
            if cached_slice is not None:
                all_slice_instructions.extend(cached_slice)
                continue

            slice_instructions = []
            targets_to_track = {descendant.target}
            
            print(f"[*] Starting Backward Slicing for '{descendant.target}' from Tick {descendant.at_tick}")
            hunting_for_control_dependency = False
            
            for tick in range(descendant.at_tick, 0, -1):
                if not targets_to_track and not hunting_for_control_dependency:
                    break # Everything for this descendant is resolved
                    
                record = self.get_trace_at_tick(tick)
                if not record:
                    continue
                    
                # --- IMPLICIT CONTROL FLOW (Control Dependency) ---
                if hunting_for_control_dependency:
                    if record.mnemonic.startswith("j") and record.mnemonic != "jmp":
                        slice_instructions.append(record)
                        # Add specific flags to track based on Jump Semantics via NEW DESCENDANTS
                        flags_added = []
                        if record.mnemonic in self.JUMP_FLAGS:
                            for f in self.JUMP_FLAGS[record.mnemonic]:
                                new_desc = Descendant(target=f, at_tick=record.tick)
                                worklist.append(new_desc)
                                flags_added.append(f)
                        hunting_for_control_dependency = False
                        print(f"  -> [Spawning Sub-Slice] Found Branch '{record.mnemonic} {record.op_str}' at Tick {record.tick}. Queued {flags_added}")
                        continue

                # Check if this instruction writes to any register OR memory address we are tracking
                writes_to_target_reg = any(target in record.regs_write for target in targets_to_track if isinstance(target, str) and not target.startswith("flag_"))
                
                tracked_mem = [t for t in targets_to_track if isinstance(t, int)]
                writes_to_target_mem = False  # Absolute Must-Alias
                may_alias_triggered = False
                pointer_regs_used = []
                
                if tracked_mem and record.mem_write:
                    pointer_regs_used = [r for r in record.regs_read if r in ('eax','ebx','ecx','edx','esi','edi','ebp','esp','rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')]
                    if not pointer_regs_used:
                        # Absolute Must-Alias (No registers used as pointers)
                        write_size = self._calculate_memory_write_size(record)
                        base_addr = record.mem_write[0]
                        affected_addresses = range(base_addr, base_addr + write_size)
                        
                        for target in tracked_mem:
                            if target in affected_addresses:
                                writes_to_target_mem = True
                                print(f"  -> [Must-Alias] Absolute write to [0x{target:x}] at Tick {record.tick} (Size: {write_size} bytes)")
                                break
                    else:
                        # Symbolic Pointer Write (May-Alias for ALL tracked memory)
                        may_alias_triggered = True
                        for ptr in pointer_regs_used:
                            new_desc = Descendant(target=ptr, at_tick=record.tick)
                            worklist.append(new_desc)
                            print(f"  -> [May-Alias] Tracking pointer '{ptr}' at Tick {record.tick} for potential aliasing with {tracked_mem}")
                
                writes_to_tracked_flag = False
                flags_to_kill = []
                
                tracked_flags = [t for t in targets_to_track if isinstance(t, str) and t.startswith("flag_")]
                if tracked_flags and any(r in record.regs_write for r in ["eflags", "rflags"]):
                    if record.mnemonic in self.MODIFIES_ALL_FLAGS:
                        writes_to_tracked_flag = True
                        flags_to_kill.extend(tracked_flags)
                        record.requested_flags.extend(tracked_flags)
                        print(f"  -> [Flag Gen] Hit {record.mnemonic} at Tick {record.tick}, which satisfies {tracked_flags}")
                    elif record.mnemonic in self.MODIFIES_ZSO_ONLY:
                        affected_flags = [f for f in tracked_flags if f != "flag_cf"]
                        if affected_flags:
                            writes_to_tracked_flag = True
                            flags_to_kill.extend(affected_flags)
                            record.requested_flags.extend(affected_flags)
                            print(f"  -> [Flag Gen] Hit {record.mnemonic} at Tick {record.tick}, which satisfies {affected_flags}")
                        elif "flag_cf" in tracked_flags:
                            print(f"  -> [Flag Ignore] Hit {record.mnemonic} at Tick {record.tick}, but it DOES NOT modify CF. Skipping!")
                
                # --- IMPLICIT DATA FLOW (JMP/CALL via Register/Memory) ---
                implicit_flow_trigger = False
                if record.mnemonic in ("jmp", "call"):
                    for op in record.regs_read:
                        if op in targets_to_track:
                            implicit_flow_trigger = True
                            print(f"  -> [Implicit Data Flow] Context-to-Physical-Interval Triggered at Tick {record.tick}")
                            # Spawn descendant for the pointer register
                            new_desc = Descendant(target=op, at_tick=record.tick)
                            worklist.append(new_desc)
                            break
                
                if writes_to_target_reg or writes_to_target_mem or implicit_flow_trigger or writes_to_tracked_flag or may_alias_triggered:
                    slice_instructions.append(record)
                    
                    # --- TAINT BREAKER DETECTION ---
                    is_taint_breaker = False
                    if len(record.regs_read) == 0 and len(record.mem_read) == 0:
                        is_taint_breaker = True
                    elif record.mnemonic in ("xor", "sub"):
                        ops = [op.strip() for op in record.op_str.split(",")]
                        if len(ops) == 2 and ops[0] == ops[1]:
                            is_taint_breaker = True
                            
                    if is_taint_breaker and record.mnemonic != 'call':
                        print(f"  -> [Taint Breaker] Hit dead-end at Tick {record.tick} via ({record.mnemonic} {record.op_str}). Switching to Control Dependency!")
                        
                    if is_taint_breaker:
                        hunting_for_control_dependency = True
                        
                    # KILL PHASE
                    if writes_to_target_reg or writes_to_tracked_flag:
                        for reg_out in record.regs_write:
                            if reg_out in targets_to_track and not reg_out.startswith("flag_"):
                                targets_to_track.remove(reg_out)
                        for f in flags_to_kill:
                            if f in targets_to_track:
                                targets_to_track.remove(f)
                                
                    if writes_to_target_mem:
                        for mem_out in record.mem_write:
                            if mem_out in targets_to_track:
                                targets_to_track.remove(mem_out)

                    # GEN PHASE
                    if not is_taint_breaker:
                        for reg_in in record.regs_read:
                            if may_alias_triggered and reg_in in pointer_regs_used:
                                continue # Already spawned as a sub-slice descendant
                            targets_to_track.add(reg_in)
                            print(f"  -> Found Ancestor Reg '{reg_in}' at Tick {record.tick} via ({record.mnemonic} {record.op_str})")
                        
                        for mem_in in record.mem_read:
                            targets_to_track.add(mem_in)
                            print(f"  -> Found Ancestor Mem '[0x{mem_in:x}]' at Tick {record.tick} via ({record.mnemonic} {record.op_str})")

            # 2. Save the resolved branch into PathTree for future use
            self.path_tree.cache_slice(descendant.target, descendant.at_tick, slice_instructions)
            all_slice_instructions.extend(slice_instructions)
            
        # Deduplicate and sort chronologically (Flat Merge)
        unique_instructions = {record.tick: record for record in all_slice_instructions}
        final_slice = [unique_instructions[tick] for tick in sorted(unique_instructions.keys(), reverse=True)]
        
        return final_slice
