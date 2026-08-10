import z3
import re
from typing import List, Dict, Tuple
from asm_analyzer.engine.tracker import TraceRecord, Tracker
REGISTER_HIERARCHY = Tracker.REGISTER_HIERARCHY

PHYSICAL_REGS = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]


class Z3Translator:
    def __init__(self, memory_provider=None):
        self.memory_provider = memory_provider
        self.solver = z3.Solver()
        self.reg_state: Dict[str, z3.BitVecRef] = {}
        self.flag_state: Dict[str, z3.BoolRef] = {}
        self.latest_versions: Dict[str, int] = {}
        self.memory_writes: List[Tuple[z3.BitVecRef, z3.BitVecRef, int]] = []
        self.current_instr: TraceRecord = None
        self.mem_read_idx = 0
        self.mem_write_idx = 0
        self.target_vars = set()
        self._taint_cache = {}
        
        # ⚡ Bolt Optimization: Pre-compute reverse register hierarchy mapping for O(1) lookups
        self._reg_to_base = {}
        for base, subs in REGISTER_HIERARCHY.items():
            for sub in subs:
                self._reg_to_base[sub] = base

    def _get_new_ssa_name(self, name: str) -> str:
        tick = self.current_instr.tick if self.current_instr else 0
        self.latest_versions[name] = tick
        return f"{name}_t{tick}"

    def _is_tainted(self, expr) -> bool:
        if not self.target_vars:
            return False
            
        stack = [(expr, False)]
        
        while stack:
            curr, children_processed = stack.pop()
            c_id = curr.hash()
            
            if c_id in self._taint_cache:
                continue
                
            if not children_processed:
                if z3.is_const(curr) and curr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                    self._taint_cache[c_id] = any(curr.eq(t) for t in self.target_vars)
                    continue
                    
                stack.append((curr, True))
                for child in curr.children():
                    stack.append((child, False))
            else:
                self._taint_cache[c_id] = any(self._taint_cache[c.hash()] for c in curr.children())
                
        return self._taint_cache[expr.hash()]

    def _get_phys_reg(self, phys_name: str) -> z3.BitVecRef:
        if phys_name not in self.reg_state:
            ssa_name = f"{phys_name}_t0"
            self.reg_state[phys_name] = z3.BitVec(ssa_name, 64)
            self.latest_versions[phys_name] = 0
        return self.reg_state[phys_name]

    def _clobber_register(self, phys_name: str):
        ssa_name = self._get_new_ssa_name(phys_name)
        new_var = z3.BitVec(ssa_name, 64)
        self.reg_state[phys_name] = new_var

    def _write_flag(self, flag_name: str, bool_val):
        ssa_name = self._get_new_ssa_name(flag_name)
        new_var = z3.Bool(ssa_name)
        self.solver.add(new_var == bool_val)
        self.flag_state[flag_name] = new_var

    def generate_flags(self, instr: TraceRecord, mnemonic: str, dst_ast, src_ast, res_ast, size: int):
        requested = instr.requested_flags
        if not requested:
            return  # Lazy Generation!

        if "flag_zf" in requested:
            self._write_flag("flag_zf", res_ast == 0)
        
        if "flag_sf" in requested:
            self._write_flag("flag_sf", z3.Extract(size - 1, size - 1, res_ast) == 1)
            
        if "flag_cf" in requested:
            if mnemonic in ["inc", "dec"]:
                pass  # inc and dec DO NOT modify CF!
            elif mnemonic == "add":
                self._write_flag("flag_cf", z3.ULT(res_ast, dst_ast))
            elif mnemonic in ["sub", "cmp"]:
                self._write_flag("flag_cf", z3.ULT(dst_ast, src_ast))
            elif mnemonic in ["and", "or", "xor", "test"]:
                self._write_flag("flag_cf", z3.BoolVal(False))
                
        if "flag_of" in requested:
            msb_dst = z3.Extract(size - 1, size - 1, dst_ast) == 1
            msb_src = z3.Extract(size - 1, size - 1, src_ast) == 1
            msb_res = z3.Extract(size - 1, size - 1, res_ast) == 1
            
            if mnemonic in ["add", "inc"]:
                self._write_flag("flag_of", z3.And(msb_dst == msb_src, msb_dst != msb_res))
            elif mnemonic in ["sub", "cmp", "dec"]:
                self._write_flag("flag_of", z3.And(msb_dst != msb_src, msb_dst != msb_res))
            elif mnemonic in ["and", "or", "xor", "test"]:
                self._write_flag("flag_of", z3.BoolVal(False))

    def generate_shift_flags(self, instr: TraceRecord, mnemonic: str, dst_val: z3.BitVecRef, dst_size: int, shift_count: z3.BitVecRef, res_ast: z3.BitVecRef):
        requested = instr.requested_flags
        if not requested:
            return

        old_zf = self.flag_state.get('flag_zf', z3.BoolVal(False))
        old_sf = self.flag_state.get('flag_sf', z3.BoolVal(False))
        old_cf = self.flag_state.get('flag_cf', z3.BoolVal(False))
        old_of = self.flag_state.get('flag_of', z3.BoolVal(False))

        if "flag_zf" in requested:
            new_zf = (res_ast == 0)
            self._write_flag("flag_zf", z3.If(shift_count == 0, old_zf, new_zf))

        if "flag_sf" in requested:
            new_sf = (z3.Extract(dst_size - 1, dst_size - 1, res_ast) == 1)
            self._write_flag("flag_sf", z3.If(shift_count == 0, old_sf, new_sf))

        new_cf = None
        if "flag_cf" in requested or "flag_of" in requested:
            one_ast = z3.BitVecVal(1, dst_size)
            if mnemonic == 'shl':
                shifted_minus_one = z3.If(shift_count == 0, dst_val, dst_val << (shift_count - one_ast))
                new_cf = (z3.LShR(shifted_minus_one, dst_size - 1) & 1) == 1
            elif mnemonic in ['shr', 'sar']:
                shifted_minus_one = z3.If(shift_count == 0, dst_val, z3.LShR(dst_val, shift_count - one_ast))
                new_cf = (shifted_minus_one & 1) == 1

            if "flag_cf" in requested:
                self._write_flag("flag_cf", z3.If(shift_count == 0, old_cf, new_cf))

        if "flag_of" in requested:
            if mnemonic == 'shl':
                msb_res = z3.Extract(dst_size - 1, dst_size - 1, res_ast) == 1
                new_of = (msb_res != new_cf)
            elif mnemonic == 'shr':
                new_of = (z3.Extract(dst_size - 1, dst_size - 1, dst_val) == 1)
            elif mnemonic == 'sar':
                new_of = z3.BoolVal(False)

            undef_of = z3.Bool(self._get_new_ssa_name("flag_of_undef"))
            self._write_flag("flag_of", z3.If(shift_count == 0, old_of, z3.If(shift_count == 1, new_of, undef_of)))

    def _read_operand(self, op_dict: dict) -> Tuple[z3.BitVecRef, int]:
        op_type = op_dict['type']
        
        # 1. Immediate value
        if op_type == 'imm':
            size = op_dict.get('size', 8) * 8
            # Handle negative Z3 bitvec values properly
            val = op_dict['value']
            if val < 0:
                val = (1 << size) + val
            return z3.BitVecVal(val, size), size
            
        # 2. Register
        if op_type == 'reg':
            op_str = op_dict['value']
            size = op_dict.get('size', 8) * 8

            # ⚡ Bolt Optimization: Replace O(N) linear scan with O(1) hash map lookup
            base_reg = self._reg_to_base.get(op_str, op_str)

            offset = 8 if op_str.endswith('h') and len(op_str) == 2 else 0

            phys_val = self._get_phys_reg(base_reg)
            extracted = z3.Extract(offset + size - 1, offset, phys_val)
            return extracted, size
                
        # 3. Memory
        if op_type == 'mem':
            addr_ast = z3.BitVecVal(op_dict['disp'], 64)
            if op_dict['base']:
                base_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['base'], 'size': 8})
                if base_ast.size() != 64: base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                addr_ast = addr_ast + base_ast
            if op_dict['index']:
                index_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['index'], 'size': 8})
                if index_ast.size() != 64: index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                addr_ast = addr_ast + (index_ast * op_dict['scale'])
            
            size = op_dict.get('size', 8) * 8
            if size == 0: size = 64
            
            # Byte-Level Read
            read_bytes = []
            
            # Smart Concretization Check
            simplified_addr = self._safe_simplify(addr_ast)
            is_concrete_addr = isinstance(simplified_addr, z3.BitVecNumRef)
            concrete_addr_val = simplified_addr.as_long() if is_concrete_addr else 0
            
            # Concolic Memory Concretization
            is_tainted_addr = self._is_tainted(addr_ast)
            
            if not is_concrete_addr and not is_tainted_addr and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_read:
                concrete_addr_val = self.current_instr.mem_read[0]
                addr_ast = z3.BitVecVal(concrete_addr_val, 64)
                is_concrete_addr = True
            elif is_tainted_addr:
                self.solver.add(z3.UGE(addr_ast, 0x10000), z3.ULE(addr_ast, 0x00007FFFFFFFFFFF))
            
            for i in range(size // 8):
                byte_addr = self._safe_simplify(addr_ast + i)
                
                byte_ast = None
                
                chain = []
                for write_addr_ast, write_byte_ast, write_size in reversed(self.memory_writes):
                    cond = (byte_addr == write_addr_ast)
                    is_t = False
                    is_f = False
                    
                    if isinstance(byte_addr, z3.BitVecNumRef) and isinstance(write_addr_ast, z3.BitVecNumRef):
                        if byte_addr.as_long() == write_addr_ast.as_long():
                            is_t = True
                        else:
                            is_f = True
                    elif byte_addr.eq(write_addr_ast):
                        is_t = True
                    else:
                        # VSA Pruning (Pointer Domain Pruning)
                        if is_tainted_addr:
                            self.solver.push()
                            self.solver.add(cond)
                            if self.solver.check() == z3.unsat:
                                is_f = True
                            self.solver.pop()

                    if is_t:
                        chain.append((True, write_byte_ast))
                        break
                    elif is_f:
                        continue
                    else:
                        chain.append((cond, write_byte_ast))
                        
                if not chain or chain[-1][0] is not True:
                    # Fetch concrete byte if address is static and provider exists
                    if is_concrete_addr and self.memory_provider:
                        try:
                            concrete_byte = self.memory_provider(concrete_addr_val + i, 1)
                            if concrete_byte:
                                byte_val = int.from_bytes(concrete_byte, byteorder='little')
                                byte_ast = z3.BitVecVal(byte_val, 8)
                                if i == 0: # Print only once per read operation to avoid flooding
                                    print(f"  -> [Smart Concretization] Resolved static memory at {hex(concrete_addr_val)} (Size: {size} bits)")
                        except Exception:
                            pass # Fallback to symbolic if read fails
                            
                    if byte_ast is None:
                        # Start with an uninitialized symbolic memory variable for THIS BYTE
                        mem_name = f"SymMemRead_{self.mem_read_idx}_t{self.current_instr.tick}_b{i}"
                        self.mem_read_idx += 1
                        byte_ast = z3.BitVec(mem_name, 8)
                        if i == 0:
                            print(f"  -> [Symbolic Memory] Falling back to unknown for symbolic address at Tick {self.current_instr.tick}")
                else:
                    byte_ast = chain.pop()[1]
                    
                while chain:
                    cond, val = chain.pop()
                    byte_ast = z3.If(cond, val, byte_ast)
                    
                read_bytes.append(byte_ast)
                
            # Concat in Little Endian (reverse order)
            if len(read_bytes) == 1:
                result_ast = read_bytes[0]
            else:
                result_ast = z3.Concat(*reversed(read_bytes))
                
            return result_ast, size
            
        return z3.BitVecVal(0, 64), 64

    def _is_concrete_tree(self, ast, memo=None):
        if memo is None: memo = {}
        ast_id = ast.get_id()
        if ast_id in memo: return memo[ast_id]
        
        if isinstance(ast, z3.BitVecNumRef):
            memo[ast_id] = True
            return True
        if z3.is_const(ast):
            memo[ast_id] = False
            return False
            
        for child in ast.children():
            if not self._is_concrete_tree(child, memo):
                memo[ast_id] = False
                return False
                
        memo[ast_id] = True
        return True

    def _safe_simplify(self, ast):
        if self._is_concrete_tree(ast):
            return z3.simplify(ast)
        return ast

    def _write_operand(self, op_dict: dict, native_val: z3.BitVecRef):
        op_type = op_dict['type']
        size = native_val.size()
        
        # 1. Register Write
        if op_type == 'reg':
            op_str = op_dict['value']
            reg_size = op_dict.get('size', 8) * 8

            # ⚡ Bolt Optimization: Replace O(N) linear scan with O(1) hash map lookup
            base_reg = self._reg_to_base.get(op_str, op_str)

            offset = 8 if op_str.endswith('h') and len(op_str) == 2 else 0

            # Sanity check: force size match
            if size != reg_size:
                if size > reg_size:
                    native_val = z3.Extract(reg_size - 1, 0, native_val)
                else:
                    native_val = z3.ZeroExt(reg_size - size, native_val)
                    
            old_phys_val = self._get_phys_reg(base_reg)

            if reg_size == 32 and offset == 0:
                new_phys_val = z3.ZeroExt(32, native_val)
            else:
                parts = []
                if offset + reg_size < 64:
                    parts.append(z3.Extract(63, offset + reg_size, old_phys_val))
                parts.append(native_val)
                if offset > 0:
                    parts.append(z3.Extract(offset - 1, 0, old_phys_val))
                
                if len(parts) == 1:
                    new_phys_val = parts[0]
                else:
                    new_phys_val = z3.Concat(*parts)

            new_phys_val = self._safe_simplify(new_phys_val)
            if isinstance(new_phys_val, z3.BitVecNumRef):
                self.reg_state[base_reg] = new_phys_val
            else:
                ssa_name = self._get_new_ssa_name(base_reg)
                new_var = z3.BitVec(ssa_name, 64)
                self.solver.add(new_var == new_phys_val)
                self.reg_state[base_reg] = new_var
            return
                
        # 2. Memory Write
        if op_type == 'mem':
            write_addr_ast = z3.BitVecVal(op_dict['disp'], 64)
            if op_dict['base']:
                base_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['base'], 'size': 8})
                if base_ast.size() != 64: base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                write_addr_ast = write_addr_ast + base_ast
            if op_dict['index']:
                index_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['index'], 'size': 8})
                if index_ast.size() != 64: index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                write_addr_ast = write_addr_ast + (index_ast * op_dict['scale'])
            
            # Concolic Memory Concretization
            is_tainted_addr = self._is_tainted(write_addr_ast)
            
            if not is_tainted_addr and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_write:
                concrete_addr_val = self.current_instr.mem_write[0]
                write_addr_ast = z3.BitVecVal(concrete_addr_val, 64)
            elif is_tainted_addr:
                self.solver.add(z3.UGE(write_addr_ast, 0x10000), z3.ULE(write_addr_ast, 0x00007FFFFFFFFFFF))

            mem_size = op_dict.get('size', size//8) * 8
            if mem_size == 0: mem_size = size
            
            val = native_val
            if val.size() > mem_size:
                val = z3.Extract(mem_size - 1, 0, val)
            elif val.size() < mem_size:
                val = z3.ZeroExt(mem_size - val.size(), val)
                
            # Byte-Level Write
            for i in range(mem_size // 8):
                byte_val = z3.Extract(i * 8 + 7, i * 8, val)
                self.memory_writes.append((self._safe_simplify(write_addr_ast + i), byte_val, 8))
            return

    def _match_sizes(self, dst_val: z3.BitVecRef, src_val: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        d_size = dst_val.size()
        s_size = src_val.size()
        if d_size > s_size:
            src_val = z3.ZeroExt(d_size - s_size, src_val)
        elif s_size > d_size:
            src_val = z3.Extract(d_size - 1, 0, src_val)
        return dst_val, src_val

    def parse_instruction(self, instr: TraceRecord):
        self.current_instr = instr
        self.mem_read_idx = 0
        self.mem_write_idx = 0
        ops = instr.operands
        
        if instr.mnemonic in ['mov', 'movzx', 'movsx', 'movsxd']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                
                
                _, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src)
                
                if instr.mnemonic == 'movzx':
                    src_val = z3.ZeroExt(dst_size - src_size, src_val) if dst_size > src_size else src_val
                elif instr.mnemonic in ['movsx', 'movsxd']:
                    src_val = z3.SignExt(dst_size - src_size, src_val) if dst_size > src_size else src_val
                else:
                    # Normal mov match sizes
                    if src_size > dst_size:
                        src_val = z3.Extract(dst_size - 1, 0, src_val)
                    elif src_size < dst_size:
                        src_val = z3.ZeroExt(dst_size - src_size, src_val)
                    
                self._write_operand(dst, src_val)
                
        elif instr.mnemonic == 'lea':
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                if src['type'] == 'mem':
                    addr_ast = z3.BitVecVal(src['disp'], 64)
                    if src['base']:
                        base_ast, _ = self._read_operand({'type': 'reg', 'value': src['base']})
                        if base_ast.size() != 64: base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                        addr_ast = addr_ast + base_ast
                    if src['index']:
                        index_ast, _ = self._read_operand({'type': 'reg', 'value': src['index']})
                        if index_ast.size() != 64: index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                        addr_ast = addr_ast + (index_ast * src['scale'])
                    
                    _, dst_size = self._read_operand(dst)
                    
                    if dst_size < 64:
                        addr_ast = z3.Extract(dst_size - 1, 0, addr_ast)
                        
                    self._write_operand(dst, addr_ast)
                
        elif instr.mnemonic in ['add', 'sub', 'xor', 'and', 'or', 'cmp', 'test']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                
                
                dst_val, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src)
                
                dst_val, src_val = self._match_sizes(dst_val, src_val)
                
                if instr.mnemonic == 'add': res = dst_val + src_val
                elif instr.mnemonic in ['sub', 'cmp']: res = dst_val - src_val
                elif instr.mnemonic == 'xor': res = dst_val ^ src_val
                elif instr.mnemonic in ['and', 'test']: res = dst_val & src_val
                elif instr.mnemonic == 'or': res = dst_val | src_val
                    
                if instr.mnemonic not in ['cmp', 'test']:
                    self._write_operand(dst, res)
                
                self.generate_flags(instr, instr.mnemonic, dst_val, src_val, res, dst_size)

        elif instr.mnemonic in ['inc', 'dec']:
            if len(ops) == 1:
                dst = ops[0]
                dst_val, dst_size = self._read_operand(dst)
                src_val = z3.BitVecVal(1, dst_size)
                
                if instr.mnemonic == 'inc': res = dst_val + src_val
                elif instr.mnemonic == 'dec': res = dst_val - src_val
                
                self._write_operand(dst, res)
                self.generate_flags(instr, instr.mnemonic, dst_val, src_val, res, dst_size)
                
        elif instr.mnemonic in ['shl', 'shr', 'sar']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                dst_val, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src)
                
                dst_val, src_val = self._match_sizes(dst_val, src_val)
                mask_val = 0x3F if dst_size == 64 else 0x1F
                shift_count = src_val & z3.BitVecVal(mask_val, dst_size)
                
                if instr.mnemonic == 'shl':
                    res = dst_val << shift_count
                elif instr.mnemonic == 'shr':
                    res = z3.LShR(dst_val, shift_count)
                elif instr.mnemonic == 'sar':
                    res = dst_val >> shift_count
                    
                self._write_operand(dst, res)
                self.generate_shift_flags(instr, instr.mnemonic, dst_val, dst_size, shift_count, res)
                
        elif instr.mnemonic.startswith('j') and instr.mnemonic != 'jmp':
            if hasattr(instr, 'jump_taken') and instr.jump_taken is not None:
                # Fetch current flags
                zf = self.flag_state.get('flag_zf', z3.BoolVal(False))
                cf = self.flag_state.get('flag_cf', z3.BoolVal(False))
                sf = self.flag_state.get('flag_sf', z3.BoolVal(False))
                of = self.flag_state.get('flag_of', z3.BoolVal(False))
                
                cond_ast = None
                m = instr.mnemonic
                if m in ['je', 'jz']: cond_ast = zf
                elif m in ['jne', 'jnz']: cond_ast = z3.Not(zf)
                elif m in ['ja', 'jnbe']: cond_ast = z3.And(z3.Not(cf), z3.Not(zf))
                elif m in ['jae', 'jnb', 'jnc']: cond_ast = z3.Not(cf)
                elif m in ['jb', 'jc', 'jnae']: cond_ast = cf
                elif m in ['jbe', 'jna']: cond_ast = z3.Or(cf, zf)
                elif m in ['jg', 'jnle']: cond_ast = z3.And(z3.Not(zf), sf == of)
                elif m in ['jge', 'jnl']: cond_ast = (sf == of)
                elif m in ['jl', 'jnge']: cond_ast = (sf != of)
                elif m in ['jle', 'jng']: cond_ast = z3.Or(zf, sf != of)
                elif m in ['js']: cond_ast = sf
                elif m in ['jns']: cond_ast = z3.Not(sf)
                elif m in ['jo']: cond_ast = of
                elif m in ['jno']: cond_ast = z3.Not(of)
                
                if cond_ast is not None:
                    if instr.jump_taken:
                        self.solver.add(cond_ast)
                        print(f"  -> [Z3 Jump Taken] Added Constraint for {instr.mnemonic} at Tick {instr.tick}: {cond_ast}")
                    else:
                        self.solver.add(z3.Not(cond_ast))
                        print(f"  -> [Z3 Jump Not Taken] Added Constraint for {instr.mnemonic} at Tick {instr.tick}: Not({cond_ast})")

        elif instr.mnemonic in ['mul', 'imul']:
            if len(ops) == 1:
                src = ops[0]
                src_val, src_size = self._read_operand(src)
                
                # Fetch implicit operand based on size
                if src_size == 8:
                    implied_val, _ = self._read_operand({'type': 'reg', 'value': 'al', 'size': 1})
                elif src_size == 16:
                    implied_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
                elif src_size == 32:
                    implied_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
                elif src_size == 64:
                    implied_val, _ = self._read_operand({'type': 'reg', 'value': 'rax', 'size': 8})
                else:
                    return # Unsupported size
                    
                # Expand to 2x width to prevent mathematical overflow during Z3 multiplication
                if instr.mnemonic == 'mul':
                    expanded_src = z3.ZeroExt(src_size, src_val)
                    expanded_impl = z3.ZeroExt(src_size, implied_val)
                else:
                    expanded_src = z3.SignExt(src_size, src_val)
                    expanded_impl = z3.SignExt(src_size, implied_val)
                    
                result_math = expanded_src * expanded_impl
                
                # Slice the expanded result back into the physical registers
                if src_size == 8:
                    self._write_operand({'type': 'reg', 'value': 'ax', 'size': 2}, result_math)
                else:
                    lower_half = z3.Extract(src_size - 1, 0, result_math)
                    upper_half = z3.Extract((src_size * 2) - 1, src_size, result_math)
                    
                    if src_size == 16:
                        self._write_operand({'type': 'reg', 'value': 'ax', 'size': 2}, lower_half)
                        self._write_operand({'type': 'reg', 'value': 'dx', 'size': 2}, upper_half)
                    elif src_size == 32:
                        self._write_operand({'type': 'reg', 'value': 'eax', 'size': 4}, lower_half)
                        self._write_operand({'type': 'reg', 'value': 'edx', 'size': 4}, upper_half)
                    elif src_size == 64:
                        self._write_operand({'type': 'reg', 'value': 'rax', 'size': 8}, lower_half)
                        self._write_operand({'type': 'reg', 'value': 'rdx', 'size': 8}, upper_half)
            elif len(ops) == 2 or len(ops) == 3:
                dst = ops[0]
                src1 = ops[1]
                src2 = ops[2] if len(ops) == 3 else ops[0] # if 2 ops: dst = dst * src1
                
                dst_val, dst_size = self._read_operand(dst)
                src1_val, _ = self._read_operand(src1)
                src2_val, _ = self._read_operand(src2)
                
                src1_val, src2_val = self._match_sizes(src1_val, src2_val)
                
                # Expand
                exp_src1 = z3.SignExt(dst_size, src1_val)
                exp_src2 = z3.SignExt(dst_size, src2_val)
                res = exp_src1 * exp_src2
                
                # Truncate back to dst_size
                final_res = z3.Extract(dst_size - 1, 0, res)
                self._write_operand(dst, final_res)
                
        elif instr.mnemonic == 'push':
            if len(ops) == 1:
                src = ops[0]
                src_val, src_size = self._read_operand(src)
                rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
                
                rsp_new = rsp_val - (src_size // 8)
                self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
                
                # Byte-Level Write directly to symbolic rsp_new
                for i in range(src_size // 8):
                    byte_val = z3.Extract(i * 8 + 7, i * 8, src_val)
                    self.memory_writes.append((self._safe_simplify(rsp_new + i), byte_val, 8))
                
        elif instr.mnemonic == 'pop':
            if len(ops) == 1:
                dst = ops[0]
                _, dst_size = self._read_operand(dst)
                rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
                
                # Read from memory symbolically at rsp_val
                read_bytes = []
                for i in range(dst_size // 8):
                    byte_addr = self._safe_simplify(rsp_val + i)
                    
                    chain = []
                    for write_addr_ast, write_byte_ast, write_size in reversed(self.memory_writes):
                        cond = (byte_addr == write_addr_ast)
                        is_t = False
                        is_f = False
                        
                        if isinstance(byte_addr, z3.BitVecNumRef) and isinstance(write_addr_ast, z3.BitVecNumRef):
                            if byte_addr.as_long() == write_addr_ast.as_long():
                                is_t = True
                            else:
                                is_f = True
                        elif byte_addr.eq(write_addr_ast):
                            is_t = True

                        if is_t:
                            chain.append((True, write_byte_ast))
                            break
                        elif is_f:
                            continue
                        else:
                            chain.append((cond, write_byte_ast))
                            
                    if not chain or chain[-1][0] is not True:
                        byte_ast = z3.BitVec(f"SymMemRead_{self.mem_read_idx}_t{self.current_instr.tick}_b{i}", 8)
                        self.mem_read_idx += 1
                    else:
                        byte_ast = chain.pop()[1]
                        
                    while chain:
                        cond, val = chain.pop()
                        byte_ast = z3.If(cond, val, byte_ast)
                        
                    read_bytes.append(byte_ast)
                    
                if len(read_bytes) == 1:
                    res_val = read_bytes[0]
                else:
                    res_val = z3.Concat(*reversed(read_bytes))
                    
                self._write_operand(dst, res_val)
                rsp_new = rsp_val + (dst_size // 8)
                self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
                
        elif instr.mnemonic == 'cdqe':
            eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
            rax_val = z3.SignExt(32, eax_val)
            self._write_operand({'type': 'reg', 'value': 'rax', 'size': 8}, rax_val)
            
        elif instr.mnemonic.startswith('set'):
            if len(ops) == 1:
                dst = ops[0]
                
                # Fetch flags with a clear warning if missing (Fallback to False)
                def get_flag_warn(name):
                    if name not in self.flag_state:
                        print(f"[!] Z3Translator WARNING: Flag '{name}' missing for '{instr.mnemonic}' at Tick {instr.tick}. Fallback to False (Missing info/Edge case not accounted for).")
                        return z3.BoolVal(False)
                    return self.flag_state[name]
                
                zf = get_flag_warn('flag_zf')
                cf = get_flag_warn('flag_cf')
                sf = get_flag_warn('flag_sf')
                of = get_flag_warn('flag_of')
                
                cond_ast = None
                m = instr.mnemonic
                if m in ['sete', 'setz']: cond_ast = zf
                elif m in ['setne', 'setnz']: cond_ast = z3.Not(zf)
                elif m in ['seta', 'setnbe']: cond_ast = z3.And(z3.Not(cf), z3.Not(zf))
                elif m in ['setae', 'setnb', 'setnc']: cond_ast = z3.Not(cf)
                elif m in ['setb', 'setc', 'setnae']: cond_ast = cf
                elif m in ['setbe', 'setna']: cond_ast = z3.Or(cf, zf)
                elif m in ['setg', 'setnle']: cond_ast = z3.And(z3.Not(zf), sf == of)
                elif m in ['setge', 'setnl']: cond_ast = (sf == of)
                elif m in ['setl', 'setnge']: cond_ast = (sf != of)
                elif m in ['setle', 'setng']: cond_ast = z3.Or(zf, sf != of)
                elif m in ['sets']: cond_ast = sf
                elif m in ['setns']: cond_ast = z3.Not(sf)
                elif m in ['seto']: cond_ast = of
                elif m in ['setno']: cond_ast = z3.Not(of)
                
                if cond_ast is not None:
                    res_val = z3.If(cond_ast, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
                    self._write_operand(dst, res_val)
                    
        elif instr.mnemonic == 'jmp':
            pass # Unconditional jumps don't change mathematical state
            
        elif instr.mnemonic == 'call':
            rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
            rsp_new = rsp_val - 8
            self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
            
            rip_val = z3.BitVecVal(instr.address + instr.size, 64)
            for i in range(8):
                byte_val = z3.Extract(i * 8 + 7, i * 8, rip_val)
                self.memory_writes.append((self._safe_simplify(rsp_new + i), byte_val, 8))
                
            is_external = False
            if 'rax' in instr.regs_write:
                is_external = True
                
            if is_external:
                print(f"  -> [Clobber] Call to external API at Tick {instr.tick}. Clobbering volatile registers.")
                for r in ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']:
                    self._clobber_register(r)

        elif instr.mnemonic == 'ret':
            rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
            rsp_new = rsp_val + 8
            
            if len(ops) == 1:
                imm = ops[0]
                if imm['type'] == 'imm':
                    rsp_new = rsp_new + imm['value']
                    
            self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
            
        elif instr.mnemonic in ['cmpxchg', 'lock cmpxchg']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                
                
                dst_val, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src)
                
                acc_reg = 'al'
                if dst_size == 16: acc_reg = 'ax'
                elif dst_size == 32: acc_reg = 'eax'
                elif dst_size == 64: acc_reg = 'rax'
                
                acc_val, _ = self._read_operand({'type': 'reg', 'value': acc_reg})
                
                dst_val, src_val = self._match_sizes(dst_val, src_val)
                acc_val, dst_val = self._match_sizes(acc_val, dst_val)
                
                # Deduce path taken from dynamic trace
                is_eq = False
                if dst['type'] == 'mem':
                    is_eq = len(instr.mem_write) > 0
                
                # Force the solver to follow the actual execution path
                if is_eq:
                    self.solver.add(acc_val == dst_val)
                    self._write_operand(dst, src_val)
                    self._write_flag('flag_zf', z3.BoolVal(True))
                else:
                    self.solver.add(acc_val != dst_val)
                    self._write_operand({'type': 'reg', 'value': acc_reg}, dst_val)
                    self._write_flag('flag_zf', z3.BoolVal(False))

        elif instr.mnemonic in ['xchg', 'lock xchg']:
            if len(ops) == 2:
                op1, op2 = ops[0], ops[1]
                
                
                val1, size1 = self._read_operand(op1)
                val2, size2 = self._read_operand(op2)
                
                val1, val2 = self._match_sizes(val1, val2)
                
                self._write_operand(op1, val2)
                self._write_operand(op2, val1)

        else:
            print(f"[!] Z3Translator WARNING: Unhandled instruction '{instr.mnemonic} {instr.op_str}' at Tick {instr.tick}. Mathematical state may be lost!")

    def translate_slice(self, slice_records: List[TraceRecord]):
        print("[+] Starting Z3 Translation Phase (Native Width Model)...")
        chronological_slice = list(reversed(slice_records))
        
        for i, instr in enumerate(chronological_slice):
            next_instr = chronological_slice[i+1] if i + 1 < len(chronological_slice) else None
            self.parse_instruction(instr)

        print("[+] Z3 Translation Complete. Assertions:")
        for assertion in self.solver.assertions():
            print(f"  {assertion}")
