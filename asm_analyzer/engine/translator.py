import z3
import re
from typing import List, Dict, Tuple
from asm_analyzer.engine.tracker import TraceRecord

PHYSICAL_REGS = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

SUB_REG_MAP = {
    'rax': ('rax', 0, 64), 'eax': ('rax', 0, 32), 'ax': ('rax', 0, 16), 'al': ('rax', 0, 8), 'ah': ('rax', 8, 8),
    'rbx': ('rbx', 0, 64), 'ebx': ('rbx', 0, 32), 'bx': ('rbx', 0, 16), 'bl': ('rbx', 0, 8), 'bh': ('rbx', 8, 8),
    'rcx': ('rcx', 0, 64), 'ecx': ('rcx', 0, 32), 'cx': ('rcx', 0, 16), 'cl': ('rcx', 0, 8), 'ch': ('rcx', 8, 8),
    'rdx': ('rdx', 0, 64), 'edx': ('rdx', 0, 32), 'dx': ('rdx', 0, 16), 'dl': ('rdx', 0, 8), 'dh': ('rdx', 8, 8),
    'rdi': ('rdi', 0, 64), 'edi': ('rdi', 0, 32), 'di': ('rdi', 0, 16),
    'rsi': ('rsi', 0, 64), 'esi': ('rsi', 0, 32), 'si': ('rsi', 0, 16),
    'rbp': ('rbp', 0, 64), 'ebp': ('rbp', 0, 32), 'bp': ('rbp', 0, 16),
    'rsp': ('rsp', 0, 64), 'esp': ('rsp', 0, 32), 'sp': ('rsp', 0, 16),
}

class Z3Translator:
    def __init__(self, memory_provider=None):
        self.memory_provider = memory_provider
        self.solver = z3.Solver()
        self.reg_state: Dict[str, z3.BitVecRef] = {}
        self.reg_state: Dict[str, z3.BitVecRef] = {}
        self.flag_state: Dict[str, z3.BoolRef] = {}
        self.latest_versions: Dict[str, int] = {}
        self.memory_writes: List[Tuple[z3.BitVecRef, z3.BitVecRef, int]] = []
        self.current_instr: TraceRecord = None
        self.mem_read_idx = 0
        self.mem_write_idx = 0

    def _parse_memory_address(self, op_str: str) -> z3.BitVecRef:
        match = re.search(r'\[(.*?)\]', op_str)
        if not match:
            return z3.BitVecVal(0, 64)
        inner = match.group(1).replace(' ', '')
        
        # Handle cases like gs: or cs:
        if ':' in inner:
            inner = inner.split(':')[1]
            
        tokens = re.findall(r'[+-]?\w+(?:\*\d+)?', inner)
        
        addr_ast = z3.BitVecVal(0, 64)
        for token in tokens:
            sign = 1
            if token.startswith('+'):
                token = token[1:]
            elif token.startswith('-'):
                sign = -1
                token = token[1:]
                
            if '*' in token:
                reg_name, scale = token.split('*')
                reg_ast, _ = self._read_operand(reg_name, hint_size=64)
                if reg_ast.size() != 64:
                    reg_ast = z3.ZeroExt(64 - reg_ast.size(), reg_ast)
                term = reg_ast * int(scale, 0)
            elif token.startswith('0x') or token.isdigit():
                term = z3.BitVecVal(int(token, 0), 64)
            elif token == 'rip':
                rip_val = self.current_instr.address + self.current_instr.size
                term = z3.BitVecVal(rip_val, 64)
            else:
                term, _ = self._read_operand(token, hint_size=64)
                if term.size() != 64:
                    term = z3.ZeroExt(64 - term.size(), term)
                    
            if sign == 1:
                addr_ast = addr_ast + term
            else:
                addr_ast = addr_ast - term
                
        return addr_ast

    def _get_new_ssa_name(self, name: str) -> str:
        tick = self.current_instr.tick if self.current_instr else 0
        self.latest_versions[name] = tick
        return f"{name}_t{tick}"

    def _get_phys_reg(self, phys_name: str) -> z3.BitVecRef:
        if phys_name not in self.reg_state:
            ssa_name = f"{phys_name}_t0"
            self.reg_state[phys_name] = z3.BitVec(ssa_name, 64)
            self.latest_versions[phys_name] = 0
        return self.reg_state[phys_name]

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

    def _read_operand(self, op_str: str, hint_size: int = 64) -> Tuple[z3.BitVecRef, int]:
        op_str = op_str.strip()
        
        # 1. Immediate value
        if op_str.startswith('0x'):
            return z3.BitVecVal(int(op_str, 16), hint_size), hint_size
        elif op_str.isdigit() or (op_str.startswith('-') and op_str[1:].isdigit()):
            return z3.BitVecVal(int(op_str), hint_size), hint_size
            
        # 2. Register
        if op_str in SUB_REG_MAP:
            phys_reg, offset, size = SUB_REG_MAP[op_str]
            phys_val = self._get_phys_reg(phys_reg)
            extracted = z3.Extract(offset + size - 1, offset, phys_val)
            return extracted, size
            
        if op_str in PHYSICAL_REGS:
            return self._get_phys_reg(op_str), 64
            
        # 3. Memory
        if 'ptr' in op_str:
            addr_ast = self._parse_memory_address(op_str)
            
            size = 64
            if 'dword' in op_str: size = 32
            elif 'word' in op_str: size = 16
            elif 'byte' in op_str: size = 8
            else: size = hint_size
            
            # Byte-Level Read
            read_bytes = []
            
            # Smart Concretization Check
            simplified_addr = z3.simplify(addr_ast)
            is_concrete_addr = isinstance(simplified_addr, z3.BitVecNumRef)
            concrete_addr_val = simplified_addr.as_long() if is_concrete_addr else 0
            
            for i in range(size // 8):
                byte_addr = addr_ast + i
                
                byte_ast = None
                
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
                
                # Chain with past byte writes chronologically
                for write_addr_ast, write_byte_ast, write_size in self.memory_writes:
                    condition = (byte_addr == write_addr_ast)
                    byte_ast = z3.If(condition, write_byte_ast, byte_ast)
                    
                read_bytes.append(byte_ast)
                
            # Concat in Little Endian (reverse order)
            if len(read_bytes) == 1:
                result_ast = read_bytes[0]
            else:
                result_ast = z3.Concat(*reversed(read_bytes))
                
            return result_ast, size
            
        return z3.BitVecVal(0, hint_size), hint_size

    def _write_operand(self, op_str: str, native_val: z3.BitVecRef):
        op_str = op_str.strip()
        size = native_val.size()
        
        # 1. Register Write
        if op_str in SUB_REG_MAP:
            phys_reg, offset, reg_size = SUB_REG_MAP[op_str]
            
            # Sanity check: force size match
            if size != reg_size:
                if size > reg_size:
                    native_val = z3.Extract(reg_size - 1, 0, native_val)
                else:
                    native_val = z3.ZeroExt(reg_size - size, native_val)
                    
            old_phys_val = self._get_phys_reg(phys_reg)
            
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
                    
            ssa_name = self._get_new_ssa_name(phys_reg)
            new_var = z3.BitVec(ssa_name, 64)
            self.solver.add(new_var == new_phys_val)
            self.reg_state[phys_reg] = new_var
            return
            
        if op_str in PHYSICAL_REGS:
            if size != 64:
                native_val = z3.ZeroExt(64 - size, native_val)
            ssa_name = self._get_new_ssa_name(op_str)
            new_var = z3.BitVec(ssa_name, 64)
            self.solver.add(new_var == native_val)
            self.reg_state[op_str] = new_var
            return
            
        # 2. Memory Write
        if 'ptr' in op_str:
            write_addr_ast = self._parse_memory_address(op_str)
            
            mem_size = 64
            if 'dword' in op_str: mem_size = 32
            elif 'word' in op_str: mem_size = 16
            elif 'byte' in op_str: mem_size = 8
            else: mem_size = size
            
            val = native_val
            if val.size() > mem_size:
                val = z3.Extract(mem_size - 1, 0, val)
            elif val.size() < mem_size:
                val = z3.ZeroExt(mem_size - val.size(), val)
                
            # Byte-Level Write
            for i in range(mem_size // 8):
                byte_val = z3.Extract(i * 8 + 7, i * 8, val)
                self.memory_writes.append((write_addr_ast + i, byte_val, 8))
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
        ops = [op.strip() for op in instr.op_str.split(',')]
        
        if instr.mnemonic in ['mov', 'movzx', 'movsx', 'movsxd']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                _, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src, hint_size=dst_size)
                
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
                addr_ast = self._parse_memory_address(src)
                _, dst_size = self._read_operand(dst)
                
                # Z3 addresses are 64-bit, truncate if destination is smaller (e.g. lea eax, [...])
                if dst_size < 64:
                    addr_ast = z3.Extract(dst_size - 1, 0, addr_ast)
                    
                self._write_operand(dst, addr_ast)
                
        elif instr.mnemonic in ['add', 'sub', 'xor', 'and', 'or', 'cmp', 'test']:
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                dst_val, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src, hint_size=dst_size)
                
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
                src_val, src_size = self._read_operand(src, hint_size=dst_size)
                
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
                    implied_val, _ = self._read_operand('al')
                elif src_size == 16:
                    implied_val, _ = self._read_operand('ax')
                elif src_size == 32:
                    implied_val, _ = self._read_operand('eax')
                elif src_size == 64:
                    implied_val, _ = self._read_operand('rax')
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
                    self._write_operand('ax', result_math)
                else:
                    lower_half = z3.Extract(src_size - 1, 0, result_math)
                    upper_half = z3.Extract((src_size * 2) - 1, src_size, result_math)
                    
                    if src_size == 16:
                        self._write_operand('ax', lower_half)
                        self._write_operand('dx', upper_half)
                    elif src_size == 32:
                        self._write_operand('eax', lower_half)
                        self._write_operand('edx', upper_half)
                    elif src_size == 64:
                        self._write_operand('rax', lower_half)
                        self._write_operand('rdx', upper_half)
            elif len(ops) == 2 or len(ops) == 3:
                dst = ops[0]
                src1 = ops[1]
                src2 = ops[2] if len(ops) == 3 else ops[1] # if 2 ops: dst = dst * src1
                
                dst_val, dst_size = self._read_operand(dst)
                src1_val, _ = self._read_operand(src1, hint_size=dst_size)
                src2_val, _ = self._read_operand(src2, hint_size=dst_size)
                
                src1_val, src2_val = self._match_sizes(src1_val, src2_val)
                
                # Expand
                exp_src1 = z3.SignExt(dst_size, src1_val)
                exp_src2 = z3.SignExt(dst_size, src2_val)
                res = exp_src1 * exp_src2
                
                # Truncate back to dst_size
                final_res = z3.Extract(dst_size - 1, 0, res)
                self._write_operand(dst, final_res)
                
        elif instr.mnemonic == 'push':
            if len(ops) == 1 and instr.mem_write:
                src = ops[0]
                addr = instr.mem_write[0]
                src_val, src_size = self._read_operand(src)
                
                size_prefix = "qword"
                if src_size == 32: size_prefix = "dword"
                elif src_size == 16: size_prefix = "word"
                elif src_size == 8: size_prefix = "byte"
                
                self._write_operand(f"{size_prefix} ptr [{hex(addr)}]", src_val)
                
        elif instr.mnemonic == 'pop':
            if len(ops) == 1 and instr.mem_read:
                dst = ops[0]
                addr = instr.mem_read[0]
                # Determine size from dst
                _, dst_size = self._read_operand(dst)
                
                size_prefix = "qword"
                if dst_size == 32: size_prefix = "dword"
                elif dst_size == 16: size_prefix = "word"
                elif dst_size == 8: size_prefix = "byte"
                
                res_val, _ = self._read_operand(f"{size_prefix} ptr [{hex(addr)}]", hint_size=dst_size)
                self._write_operand(dst, res_val)
                
        elif instr.mnemonic == 'jmp':
            pass # Unconditional jumps don't change mathematical state
            
        else:
            print(f"[!] Z3Translator WARNING: Unhandled instruction '{instr.mnemonic} {instr.op_str}' at Tick {instr.tick}. Mathematical state may be lost!")

    def translate_slice(self, slice_records: List[TraceRecord]):
        print("[+] Starting Z3 Translation Phase (Native Width Model)...")
        chronological_slice = list(reversed(slice_records))
        
        for instr in chronological_slice:
            if instr.mnemonic in ['call']:
                print(f"  -> [Ignored] Skipping call: '{instr.mnemonic} {instr.op_str}' at Tick {instr.tick}")
                continue
            if instr.mnemonic in ['sub', 'add'] and 'rsp' in instr.op_str:
                print(f"  -> [Ignored] Skipping stack pointer math: '{instr.mnemonic} {instr.op_str}' at Tick {instr.tick}")
                continue
            self.parse_instruction(instr)

        print("[+] Z3 Translation Complete. Assertions:")
        for assertion in self.solver.assertions():
            print(f"  {assertion}")
