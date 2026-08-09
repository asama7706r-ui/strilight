from typing import List, Dict, Any, Optional
from collections import deque

class TraceRecord:
    def __init__(self, tick: int, address: int, size: int, mnemonic: str, op_str: str, thread_id: int = 0):
        self.tick = tick
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.thread_id = thread_id
        
        # Details about what this instruction read or wrote
        self.regs_read: List[str] = []
        self.regs_write: List[str] = []
        self.mem_read: List[int] = []
        self.mem_write: List[int] = []
        self.requested_flags: List[str] = []  # For Lazy Flag Generation
        self.jump_taken: Optional[bool] = None # Added for Constraint Translation
        self.operands: List[Dict[str, Any]] = [] # Structured operands from Capstone

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


class BackwardSliceTracker:
    def __init__(self, ctx: 'Tracker'):
        self.ctx = ctx

    def build_backward_slice(self, initial_descendant: Descendant) -> List[TraceRecord]:
        worklist = deque([initial_descendant])
        all_slice_instructions = []
        global_end_tick = initial_descendant.at_tick
        
        while worklist:
            descendant = worklist.popleft() # BFS
            
            # 1. Check PathTree Memoization Cache first
            cached_slice = self.ctx.path_tree.get_cached_slice(descendant.target, descendant.at_tick)
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
                    
                record = self.ctx.get_trace_at_tick(tick)
                if not record:
                    continue
                    
                # --- IMPLICIT CONTROL FLOW (Control Dependency) ---
                if hunting_for_control_dependency:
                    if record.mnemonic.startswith("j") and record.mnemonic != "jmp":
                        # EVALUATE JUMP TAKEN
                        next_record = self.ctx.get_trace_at_tick(record.tick + 1)
                        if next_record:
                            try:
                                target_addr = int(record.op_str, 16)
                                record.jump_taken = (next_record.address == target_addr)
                            except ValueError:
                                pass
                                
                        slice_instructions.append(record)
                        # Add specific flags to track based on Jump Semantics via NEW DESCENDANTS
                        flags_added = []
                        if record.mnemonic in self.ctx.JUMP_FLAGS:
                            for f in self.ctx.JUMP_FLAGS[record.mnemonic]:
                                new_desc = Descendant(target=f, at_tick=record.tick)
                                worklist.append(new_desc)
                                flags_added.append(f)
                        hunting_for_control_dependency = False
                        print(f"  -> [Spawning Sub-Slice] Found Branch '{record.mnemonic} {record.op_str}' at Tick {record.tick}. Queued {flags_added}")
                        continue

                # Check if this instruction writes to any register OR memory address we are tracking
                tracked_bases = {self.ctx.REG_TO_BASE.get(t, t) for t in targets_to_track if isinstance(t, str) and not t.startswith("flag_")}
                writes_to_target_reg = any(self.ctx.REG_TO_BASE.get(r, r) in tracked_bases for r in record.regs_write if not r.startswith("flag_"))
                
                tracked_mem = [t for t in targets_to_track if isinstance(t, int)]
                writes_to_target_mem = False  # Absolute Must-Alias
                may_alias_triggered = False
                pointer_regs_used = []
                
                if tracked_mem and record.mem_write:
                    pointer_regs_used = [r for r in record.regs_read if r in {'eax','ebx','ecx','edx','esi','edi','rax','rbx','rcx','rdx','rsi','rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}]
                    if not pointer_regs_used:
                        # Absolute Must-Alias (No registers used as pointers)
                        write_size = self.ctx._calculate_memory_access_size(record)
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
                            print(f"  -> [May-Alias] Tracking pointer '{ptr}' at Tick {record.tick} for potential aliasing with {len(tracked_mem)} addresses")
                            
                            # Pruning Constraints: Launch Forward Tracker to gather path constraints on this pointer
                            print(f"  -> [Bidirectional Slicing] Launching Forward Tracker on '{ptr}' to prune Z3 constraints up to Tick {global_end_tick}...")
                            forward_slice = self.ctx.build_forward_slice(target=ptr, start_tick=record.tick, end_tick=global_end_tick, disable_fallback=True)
                            slice_instructions.extend(forward_slice)
                
                writes_to_tracked_flag = False
                flags_to_kill = []
                
                tracked_flags = [t for t in targets_to_track if isinstance(t, str) and t.startswith("flag_")]
                if tracked_flags and any(r in record.regs_write for r in ["eflags", "rflags"]):
                    if record.mnemonic in self.ctx.MODIFIES_ALL_FLAGS:
                        writes_to_tracked_flag = True
                        flags_to_kill.extend(tracked_flags)
                        record.requested_flags.extend(tracked_flags)
                        print(f"  -> [Flag Gen] Hit {record.mnemonic} at Tick {record.tick}, which satisfies {tracked_flags}")
                    elif record.mnemonic in self.ctx.MODIFIES_ZSO_ONLY:
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
                        if len(record.operands) == 2:
                            op0, op1 = record.operands[0], record.operands[1]
                            if op0['type'] == 'reg' and op1['type'] == 'reg' and op0['value'] == op1['value']:
                                is_taint_breaker = True
                            
                    if is_taint_breaker and record.mnemonic != 'call':
                        print(f"  -> [Taint Breaker] Hit dead-end at Tick {record.tick} via ({record.mnemonic} {record.op_str}). Switching to Control Dependency!")
                        
                    if is_taint_breaker:
                        hunting_for_control_dependency = False
                        
                    # KILL PHASE
                    if writes_to_target_reg or writes_to_tracked_flag:
                        for reg_out in record.regs_write:
                            base_out = self.ctx.REG_TO_BASE.get(reg_out, reg_out)
                            to_remove = [t for t in targets_to_track if isinstance(t, str) and not t.startswith("flag_") and self.ctx.REG_TO_BASE.get(t, t) == base_out]
                            for t in to_remove:
                                targets_to_track.remove(t)
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
                            base_in = self.ctx.REG_TO_BASE.get(reg_in, reg_in)
                            if may_alias_triggered and base_in in [self.ctx.REG_TO_BASE.get(p, p) for p in pointer_regs_used]:
                                continue # Already spawned as a sub-slice descendant
                            targets_to_track.add(reg_in)
                            print(f"  -> Found Ancestor Reg '{reg_in}' at Tick {record.tick} via ({record.mnemonic} {record.op_str})")
                            
                        # INJECT SETCC FLAGS
                        if hasattr(self.ctx, 'SET_FLAGS') and record.mnemonic in self.ctx.SET_FLAGS:
                            for f in self.ctx.SET_FLAGS[record.mnemonic]:
                                targets_to_track.add(f)
                                print(f"  -> Found Ancestor Flag '{f}' at Tick {record.tick} via ({record.mnemonic})")
                        
                        if record.mem_read:
                            read_size = self.ctx._calculate_memory_access_size(record)
                            for mem_in in record.mem_read:
                                for offset in range(read_size):
                                    targets_to_track.add(mem_in + offset)
                                print(f"  -> Found Ancestor Mem '[0x{mem_in:x}]' (Size: {read_size}) at Tick {record.tick} via ({record.mnemonic} {record.op_str})")

            # 2. Save the resolved branch into PathTree for future use
            self.ctx.path_tree.cache_slice(descendant.target, descendant.at_tick, slice_instructions)
            all_slice_instructions.extend(slice_instructions)
            
        # Deduplicate and sort chronologically (Flat Merge)
        unique_instructions = {record.tick: record for record in all_slice_instructions}
        final_slice = [unique_instructions[tick] for tick in sorted(unique_instructions.keys(), reverse=True)]
        
        return final_slice


class ForwardSliceTracker:
    def __init__(self, ctx: 'Tracker'):
        self.ctx = ctx
        
    def build_forward_slice(self, target: Any, start_tick: int, end_tick: Optional[int] = None, disable_fallback: bool = False) -> List[TraceRecord]:
        """
        Walks forwards using a linear single-pass to propagate taint from start_tick to the end.
        """
        cache_key = (target, start_tick, end_tick)
        if hasattr(self.ctx, 'forward_cache') and cache_key in self.ctx.forward_cache:
            print(f"[*] Forward Cache Hit for '{target}' from Tick {start_tick}")
            return self.ctx.forward_cache[cache_key]

        targets_to_track = {target}
        slice_instructions = []
        flag_generators: Dict[str, TraceRecord] = {}
        
        print(f"[*] Starting Forward Slicing for '{target}' from Tick {start_tick} to {end_tick if end_tick else 'End'}")
        
        limit = end_tick if end_tick is not None else len(self.ctx.trace_history)
        for tick in range(start_tick, limit + 1):
            if not targets_to_track:
                print(f"  -> [Forward Taint Empty] All taints killed. Stopping forward trace at Tick {tick}.")
                break
                
            record = self.ctx.get_trace_at_tick(tick)
            if not record:
                continue
                
            # --- 1. Kill Phase (Taint Breakers) ---
            is_taint_breaker = False
            if len(record.regs_read) == 0 and len(record.mem_read) == 0:
                is_taint_breaker = True
            elif record.mnemonic in ("xor", "sub"):
                if len(record.operands) == 2:
                    op0, op1 = record.operands[0], record.operands[1]
                    if op0['type'] == 'reg' and op1['type'] == 'reg' and op0['value'] == op1['value']:
                        is_taint_breaker = True
            
            if is_taint_breaker and record.mnemonic != 'call':
                killed_regs = []
                for reg_out in record.regs_write:
                    base_out = self.ctx.REG_TO_BASE.get(reg_out, reg_out)
                    to_remove = [t for t in targets_to_track if isinstance(t, str) and not t.startswith("flag_") and self.ctx.REG_TO_BASE.get(t, t) == base_out]
                    for t in to_remove:
                        targets_to_track.remove(t)
                        killed_regs.append(t)
                
                # Check mem kill
                if record.mem_write:
                    write_size = self.ctx._calculate_memory_access_size(record)
                    base_addr = record.mem_write[0]
                    affected_addresses = range(base_addr, base_addr + write_size)
                    killed_mem = []
                    for addr in list(targets_to_track):
                        if isinstance(addr, int) and addr in affected_addresses:
                            targets_to_track.remove(addr)
                            killed_mem.append(addr)
                    if killed_mem:
                        print(f"  -> [Forward Taint Killed] Memory {killed_mem} killed at Tick {record.tick}")
                
                if killed_regs:
                    print(f"  -> [Forward Taint Killed] Registers {killed_regs} killed at Tick {record.tick} via ({record.mnemonic} {record.op_str})")
                
                # We skip taint propagation if it's a pure kill instruction
                continue

            # --- 2. Gen Phase (Taint Propagation) ---
            tracked_bases = {self.ctx.REG_TO_BASE.get(t, t) for t in targets_to_track if isinstance(t, str) and not t.startswith("flag_")}
            reads_from_target_reg = any(self.ctx.REG_TO_BASE.get(r, r) in tracked_bases for r in record.regs_read if not r.startswith("flag_"))
            reads_from_target_mem = any(m in targets_to_track for m in record.mem_read)
            
            # For flags, we see if it's a conditional jump and we track the required flags
            reads_tracked_flag = False
            tracked_flags = [t for t in targets_to_track if isinstance(t, str) and t.startswith("flag_")]
            if tracked_flags:
                required_flags = []
                if record.mnemonic in self.ctx.JUMP_FLAGS:
                    required_flags.extend(self.ctx.JUMP_FLAGS[record.mnemonic])
                if hasattr(self.ctx, 'SET_FLAGS') and record.mnemonic in self.ctx.SET_FLAGS:
                    required_flags.extend(self.ctx.SET_FLAGS[record.mnemonic])
                
                matched_flags = [f for f in tracked_flags if f in required_flags]
                if matched_flags:
                    reads_tracked_flag = True
                    print(f"  -> [Forward Constraint] Hit {record.mnemonic} at Tick {record.tick} which depends on {matched_flags}")
                    # RETROACTIVE PULL
                    for f in matched_flags:
                        if f in flag_generators:
                            gen_record = flag_generators[f]
                            if f not in gen_record.requested_flags:
                                gen_record.requested_flags.append(f)
                                print(f"  -> [Retroactive Pull] Requested {f} from Tick {gen_record.tick}")

            if reads_from_target_reg or reads_from_target_mem or reads_tracked_flag:
                # EVALUATE JUMP TAKEN
                if reads_tracked_flag and record.mnemonic.startswith("j"):
                    next_record = self.ctx.get_trace_at_tick(record.tick + 1)
                    if next_record:
                        try:
                            target_addr = int(record.op_str, 16)
                            record.jump_taken = (next_record.address == target_addr)
                        except ValueError:
                            pass
                            
                slice_instructions.append(record)
                
                # Backward Fallback for unknown variables
                if not reads_tracked_flag and not disable_fallback: # Ignore fallback for jumps (they just read flags)
                    unknown_regs = [r for r in record.regs_read if r not in targets_to_track and not r.startswith("flag_") and r not in {'eip', 'rip', 'eflags', 'rflags'}]
                    if unknown_regs:
                        print(f"  -> [Forward Backward-Fallback] Found unknown registers {unknown_regs} at Tick {record.tick}. Initiating backward trace!")
                        backward_tracer = BackwardSliceTracker(self.ctx)
                        for unk in unknown_regs:
                            fallback_slice = backward_tracer.build_backward_slice(Descendant(target=unk, at_tick=record.tick))
                            slice_instructions.extend(fallback_slice)
                
                # Propagate taint to output registers
                for reg_out in record.regs_write:
                    base_out = self.ctx.REG_TO_BASE.get(reg_out, reg_out)
                    if not any(self.ctx.REG_TO_BASE.get(t, t) == base_out for t in targets_to_track if isinstance(t, str) and not t.startswith("flag_")):
                        targets_to_track.add(reg_out)
                        print(f"  -> [Forward Taint Gen] Tainted Register '{reg_out}' at Tick {record.tick}")
                
                # Propagate taint to output memory
                if record.mem_write:
                    # In dynamic trace, mem_write contains absolute addresses
                    write_size = self.ctx._calculate_memory_access_size(record)
                    base_addr = record.mem_write[0]
                    affected_addresses = range(base_addr, base_addr + write_size)
                    for addr in affected_addresses:
                        if addr not in targets_to_track:
                            targets_to_track.add(addr)
                            print(f"  -> [Forward Taint Gen] Tainted Memory '[0x{addr:x}]' at Tick {record.tick}")

                # Propagate taint to output flags (e.g. from CMP or ADD)
                if record.mnemonic in self.ctx.MODIFIES_ALL_FLAGS or record.mnemonic in self.ctx.MODIFIES_ZSO_ONLY:
                    flags_to_taint = ["flag_zf", "flag_sf", "flag_of"]
                    if record.mnemonic in self.ctx.MODIFIES_ALL_FLAGS:
                        flags_to_taint.append("flag_cf")
                    
                    added_flags = []
                    for f in flags_to_taint:
                        # Update the generator dict regardless of if it was already tracked
                        flag_generators[f] = record
                        if f not in targets_to_track:
                            targets_to_track.add(f)
                            added_flags.append(f)
                            
                    if added_flags:
                        print(f"  -> [Forward Flag Taint] Tainted flags {added_flags} at Tick {record.tick} via {record.mnemonic}")
            else:
                # KILL PHASE for untainted flags
                if record.mnemonic in self.ctx.MODIFIES_ALL_FLAGS or record.mnemonic in self.ctx.MODIFIES_ZSO_ONLY:
                    killed_flags = []
                    for f in ["flag_zf", "flag_sf", "flag_of", "flag_cf"]:
                        if f in targets_to_track:
                            targets_to_track.remove(f)
                            killed_flags.append(f)
                        if f in flag_generators:
                            del flag_generators[f]
                    if killed_flags:
                        print(f"  -> [Forward Taint Killed] Flags {killed_flags} killed at Tick {record.tick} via {record.mnemonic} (Untainted inputs)")
                        
        # Deduplicate and sort chronologically (Flat Merge)
        unique_instructions = {record.tick: record for record in slice_instructions}
        final_slice = [unique_instructions[tick] for tick in sorted(unique_instructions.keys())]
        
        if hasattr(self.ctx, 'forward_cache'):
            self.ctx.forward_cache[cache_key] = final_slice
            
        return final_slice


class Tracker:
    MODIFIES_ALL_FLAGS = {"add", "sub", "cmp", "test", "and", "or", "xor", "shl", "shr", "cmpxchg", "lock cmpxchg"}
    MODIFIES_ZSO_ONLY = {"inc", "dec"}
    SET_FLAGS = {
        "sete": ["flag_zf"], "setz": ["flag_zf"],
        "setne": ["flag_zf"], "setnz": ["flag_zf"],
        "seta": ["flag_cf", "flag_zf"], "setnbe": ["flag_cf", "flag_zf"],
        "setae": ["flag_cf"], "setnb": ["flag_cf"], "setnc": ["flag_cf"],
        "setb": ["flag_cf"], "setnae": ["flag_cf"], "setc": ["flag_cf"],
        "setbe": ["flag_cf", "flag_zf"], "setna": ["flag_cf", "flag_zf"],
        "setg": ["flag_zf", "flag_sf", "flag_of"], "setnle": ["flag_zf", "flag_sf", "flag_of"],
        "setge": ["flag_sf", "flag_of"], "setnl": ["flag_sf", "flag_of"],
        "setl": ["flag_sf", "flag_of"], "setnge": ["flag_sf", "flag_of"],
        "setle": ["flag_zf", "flag_sf", "flag_of"], "setng": ["flag_zf", "flag_sf", "flag_of"],
        "sets": ["flag_sf"], "setns": ["flag_sf"],
        "seto": ["flag_of"], "setno": ["flag_of"]
    }
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

    REGISTER_HIERARCHY = {
        "rax": {"rax", "eax", "ax", "al", "ah"},
        "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
        "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},
        "rsp": {"rsp", "esp", "sp", "spl"},
        "r8": {"r8", "r8d", "r8w", "r8b"},
        "r9": {"r9", "r9d", "r9w", "r9b"},
        "r10": {"r10", "r10d", "r10w", "r10b"},
        "r11": {"r11", "r11d", "r11w", "r11b"},
        "r12": {"r12", "r12d", "r12w", "r12b"},
        "r13": {"r13", "r13d", "r13w", "r13b"},
        "r14": {"r14", "r14d", "r14w", "r14b"},
        "r15": {"r15", "r15d", "r15w", "r15b"},
    }

    REG_TO_BASE = {}
    for base, subs in REGISTER_HIERARCHY.items():
        for sub in subs:
            REG_TO_BASE[sub] = base

    def _calculate_memory_access_size(self, record: TraceRecord) -> int:
        for op in record.operands:
            if op['type'] == 'mem' and op.get('size'):
                return op['size']

        # Fallback to register sizes if memory size is not found natively in operands
        write_size = 1
        for reg in record.regs_read:
            if reg in self.REGISTER_SIZES:
                write_size = max(write_size, self.REGISTER_SIZES[reg])
        return write_size

    def __init__(self):
        self.trace_history: List[TraceRecord] = []
        from asm_analyzer.engine.path_tree import PathTree
        self.path_tree = PathTree()
        self.forward_cache: Dict[tuple, List['TraceRecord']] = {}
    
    def add_trace(self, record: TraceRecord):
        """Append an executed instruction to the history."""
        self.trace_history.append(record)
        
    def get_trace_at_tick(self, tick: int) -> Optional[TraceRecord]:
        if 0 < tick <= len(self.trace_history):
            return self.trace_history[tick - 1]
        return None

    def build_backward_slice(self, initial_descendant: Descendant) -> List[TraceRecord]:
        """
        Delegates to BackwardSliceTracker
        """
        backward_tracker = BackwardSliceTracker(self)
        return backward_tracker.build_backward_slice(initial_descendant)

    def build_forward_slice(self, target: Any, start_tick: int, end_tick: Optional[int] = None, disable_fallback: bool = False) -> List[TraceRecord]:
        """
        Delegates to ForwardSliceTracker
        """
        tracer = ForwardSliceTracker(self)
        return tracer.build_forward_slice(target, start_tick, end_tick=end_tick, disable_fallback=disable_fallback)
