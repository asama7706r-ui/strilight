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
    def __init__(self):
        self.solver = z3.Solver()
        self.reg_state: Dict[str, z3.BitVecRef] = {}
        self.mem_state: Dict[str, z3.BitVecRef] = {}
        self.flag_state: Dict[str, z3.BoolRef] = {}
        self.ssa_versions: Dict[str, int] = {}

    def _get_new_ssa_name(self, name: str) -> str:
        if name not in self.ssa_versions:
            self.ssa_versions[name] = 0
        else:
            self.ssa_versions[name] += 1
        return f"{name}_{self.ssa_versions[name]}"

    def _get_phys_reg(self, phys_name: str) -> z3.BitVecRef:
        if phys_name not in self.reg_state:
            ssa_name = self._get_new_ssa_name(phys_name)
            self.reg_state[phys_name] = z3.BitVec(ssa_name, 64)
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
            mem_name = op_str.replace('dword ptr ', 'Mem_').replace('qword ptr ', 'Mem_').replace('byte ptr ', 'Mem_').replace('word ptr ', 'Mem_')
            mem_name = mem_name.replace('[', '').replace(']', '').replace(' ', '').replace('-', '_minus_').replace('+', '_plus_')
            
            size = 64
            if 'dword' in op_str: size = 32
            elif 'word' in op_str: size = 16
            elif 'byte' in op_str: size = 8
            else: size = hint_size
            
            if mem_name not in self.mem_state:
                ssa_name = self._get_new_ssa_name(mem_name)
                self.mem_state[mem_name] = z3.BitVec(ssa_name, size)
            
            return self.mem_state[mem_name], size
            
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
            mem_name = op_str.replace('dword ptr ', 'Mem_').replace('qword ptr ', 'Mem_').replace('byte ptr ', 'Mem_').replace('word ptr ', 'Mem_')
            mem_name = mem_name.replace('[', '').replace(']', '').replace(' ', '').replace('-', '_minus_').replace('+', '_plus_')
            
            mem_size = 64
            if 'dword' in op_str: mem_size = 32
            elif 'word' in op_str: mem_size = 16
            elif 'byte' in op_str: mem_size = 8
            else: mem_size = size
            
            if size != mem_size:
                if size > mem_size:
                    native_val = z3.Extract(mem_size - 1, 0, native_val)
                else:
                    native_val = z3.ZeroExt(mem_size - size, native_val)
            
            ssa_name = self._get_new_ssa_name(mem_name)
            new_var = z3.BitVec(ssa_name, mem_size)
            self.solver.add(new_var == native_val)
            self.mem_state[mem_name] = new_var

    def _match_sizes(self, dst_val: z3.BitVecRef, src_val: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        d_size = dst_val.size()
        s_size = src_val.size()
        if d_size > s_size:
            src_val = z3.ZeroExt(d_size - s_size, src_val)
        elif s_size > d_size:
            src_val = z3.Extract(d_size - 1, 0, src_val)
        return dst_val, src_val

    def parse_instruction(self, instr: TraceRecord):
        ops = [op.strip() for op in instr.op_str.split(',')]
        
        if instr.mnemonic == 'mov':
            if len(ops) == 2:
                dst, src = ops[0], ops[1]
                _, dst_size = self._read_operand(dst)
                src_val, src_size = self._read_operand(src, hint_size=dst_size)
                
                # Match sizes
                if src_size > dst_size:
                    src_val = z3.Extract(dst_size - 1, 0, src_val)
                elif src_size < dst_size:
                    src_val = z3.ZeroExt(dst_size - src_size, src_val)
                    
                self._write_operand(dst, src_val)
                
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

    def translate_slice(self, slice_records: List[TraceRecord]):
        print("[+] Starting Z3 Translation Phase (Native Width Model)...")
        chronological_slice = list(reversed(slice_records))
        
        for instr in chronological_slice:
            if instr.mnemonic in ['push', 'pop', 'call']:
                continue
            if instr.mnemonic in ['sub', 'add'] and 'rsp' in instr.op_str:
                continue
            self.parse_instruction(instr)

        print("[+] Z3 Translation Complete. Assertions:")
        for assertion in self.solver.assertions():
            print(f"  {assertion}")
