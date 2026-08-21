import z3
import re
from typing import List, Dict, Tuple
from asm_analyzer.engine.tracker import TraceRecord
from asm_analyzer.engine.x86_defs import REGISTER_HIERARCHY, PHYSICAL_REGS, REG_TO_BASE

class Z3Translator:

    def __init__(self, memory_provider=None):
        self.memory_provider = memory_provider
        self.solver = z3.Optimize()
        self.reg_state: Dict[str, z3.BitVecRef] = {}
        self.flag_state: Dict[str, z3.BoolRef] = {}
        self.latest_versions: Dict[str, int] = {}
        self.memory_writes: List[Tuple[z3.BitVecRef, z3.BitVecRef, int]] = []
        self.concrete_memory: Dict[int, z3.BitVecRef] = {}
        self.current_instr: TraceRecord = None
        self.mem_read_idx = 0
        self.mem_write_idx = 0
        self.target_vars = set()
        self.tracked_constraints: Dict[str, Tuple[z3.BoolRef, str]] = {}
        self._taint_cache = {}
        self._reg_to_base = REG_TO_BASE
        self.handlers = {
            # Data Movement & Extension
            'mov': self._handle_mov,
            'movzx': self._handle_mov,
            'movsx': self._handle_mov,
            'movsxd': self._handle_mov,
            'lea': self._handle_lea,
            'cbw': self._handle_cbw,
            'cwde': self._handle_cwde,
            'cdqe': self._handle_cdqe,
            'cwd': self._handle_cwd,
            'cdq': self._handle_cdq,
            'cqo': self._handle_cqo,

            # Arithmetic & Logic
            'add': self._handle_math,
            'sub': self._handle_math,
            'xor': self._handle_math,
            'and': self._handle_math,
            'or': self._handle_math,
            'cmp': self._handle_math,
            'test': self._handle_math,
            'inc': self._handle_inc_dec,
            'dec': self._handle_inc_dec,
            'shl': self._handle_shift,
            'shr': self._handle_shift,
            'sar': self._handle_shift,
            'mul': self._handle_mul,
            'imul': self._handle_mul,

            # Stack & Control Flow
            'push': self._handle_push,
            'pop': self._handle_pop,
            'jmp': self._handle_jmp,
            'call': self._handle_call,
            'ret': self._handle_ret,

            # Atomic & Exchange
            'cmpxchg': self._handle_cmpxchg,
            'lock cmpxchg': self._handle_cmpxchg,
            'xchg': self._handle_xchg,
            'lock xchg': self._handle_xchg,

            # Conditional Jumps (Jcc)
            'je': self._handle_jcc,
            'jz': self._handle_jcc,
            'jne': self._handle_jcc,
            'jnz': self._handle_jcc,
            'ja': self._handle_jcc,
            'jnbe': self._handle_jcc,
            'jae': self._handle_jcc,
            'jnb': self._handle_jcc,
            'jnc': self._handle_jcc,
            'jb': self._handle_jcc,
            'jc': self._handle_jcc,
            'jnae': self._handle_jcc,
            'jbe': self._handle_jcc,
            'jna': self._handle_jcc,
            'jg': self._handle_jcc,
            'jnle': self._handle_jcc,
            'jge': self._handle_jcc,
            'jnl': self._handle_jcc,
            'jl': self._handle_jcc,
            'jnge': self._handle_jcc,
            'jle': self._handle_jcc,
            'jng': self._handle_jcc,
            'js': self._handle_jcc,
            'jns': self._handle_jcc,
            'jo': self._handle_jcc,
            'jno': self._handle_jcc,

            # Conditional Sets (Setcc)
            'sete': self._handle_setcc,
            'setz': self._handle_setcc,
            'setne': self._handle_setcc,
            'setnz': self._handle_setcc,
            'seta': self._handle_setcc,
            'setnbe': self._handle_setcc,
            'setae': self._handle_setcc,
            'setnb': self._handle_setcc,
            'setnc': self._handle_setcc,
            'setb': self._handle_setcc,
            'setc': self._handle_setcc,
            'setnae': self._handle_setcc,
            'setbe': self._handle_setcc,
            'setna': self._handle_setcc,
            'setg': self._handle_setcc,
            'setnle': self._handle_setcc,
            'setge': self._handle_setcc,
            'setnl': self._handle_setcc,
            'setl': self._handle_setcc,
            'setnge': self._handle_setcc,
            'setle': self._handle_setcc,
            'setng': self._handle_setcc,
            'sets': self._handle_setcc,
            'setns': self._handle_setcc,
            'seto': self._handle_setcc,
            'setno': self._handle_setcc,
        }

    def _get_new_ssa_name(self, name: str) -> str:
        if self.current_instr:
            tick = self.current_instr.tick
        else:
            tick = self.latest_versions.get(name, 0) + 1
        self.latest_versions[name] = tick
        return f'{name}_t{tick}'

    def _is_tainted(self, expr) -> bool:
        if not self.target_vars:
            return False
        if isinstance(expr, (int, z3.BitVecNumRef, z3.BoolRef)) and not z3.is_const(expr):
            return False
        if not hasattr(expr, 'get_id'):
            return False
        expr_id = expr.get_id()
        if expr_id in self._taint_cache:
            return self._taint_cache[expr_id]

        target_ids = {t.get_id() for t in self.target_vars if hasattr(t, 'get_id')}
        
        visited = set()
        stack = [expr]
        is_t = False
        while stack:
            curr = stack.pop()
            if not hasattr(curr, 'get_id'):
                continue
            cid = curr.get_id()
            if cid in visited:
                continue
            visited.add(cid)
            if cid in self._taint_cache:
                if self._taint_cache[cid]:
                    is_t = True
                    break
                continue
            if cid in target_ids or curr in self.target_vars:
                is_t = True
                break
            for child in curr.children():
                stack.append(child)
                
        self._taint_cache[expr_id] = is_t
        return is_t

    def _get_phys_reg(self, phys_name: str) -> z3.BitVecRef:
        if phys_name not in self.reg_state:
            ssa_name = f'{phys_name}_t0'
            self.reg_state[phys_name] = z3.BitVec(ssa_name, 64)
            self.latest_versions[phys_name] = 0
        return self.reg_state[phys_name]

    def _clobber_register(self, phys_name: str):
        ssa_name = self._get_new_ssa_name(phys_name)
        new_var = z3.BitVec(ssa_name, 64)
        self.reg_state[phys_name] = new_var

    def _write_flag(self, flag_name: str, bool_val):
        self.flag_state[flag_name] = bool_val

    def generate_flags(self, instr: TraceRecord, mnemonic: str, dst_ast, src_ast, res_ast, size: int):
        requested = instr.requested_flags
        if not requested:
            return
        if 'flag_zf' in requested:
            self._write_flag('flag_zf', res_ast == 0)
        if 'flag_sf' in requested:
            self._write_flag('flag_sf', z3.Extract(size - 1, size - 1, res_ast) == 1)
        if 'flag_cf' in requested:
            if mnemonic in ['inc', 'dec']:
                pass
            elif mnemonic == 'add':
                self._write_flag('flag_cf', z3.ULT(res_ast, dst_ast))
            elif mnemonic in ['sub', 'cmp']:
                self._write_flag('flag_cf', z3.ULT(dst_ast, src_ast))
            elif mnemonic in ['and', 'or', 'xor', 'test']:
                self._write_flag('flag_cf', z3.BoolVal(False))
        if 'flag_of' in requested:
            msb_dst = z3.Extract(size - 1, size - 1, dst_ast) == 1
            msb_src = z3.Extract(size - 1, size - 1, src_ast) == 1
            msb_res = z3.Extract(size - 1, size - 1, res_ast) == 1
            if mnemonic in ['add', 'inc']:
                self._write_flag('flag_of', z3.And(msb_dst == msb_src, msb_dst != msb_res))
            elif mnemonic in ['sub', 'cmp', 'dec']:
                self._write_flag('flag_of', z3.And(msb_dst != msb_src, msb_dst != msb_res))
            elif mnemonic in ['and', 'or', 'xor', 'test']:
                self._write_flag('flag_of', z3.BoolVal(False))

    def generate_shift_flags(self, instr: TraceRecord, mnemonic: str, dst_val: z3.BitVecRef, dst_size: int, shift_count: z3.BitVecRef, res_ast: z3.BitVecRef):
        requested = instr.requested_flags
        if not requested:
            return
        old_zf = self.flag_state.get('flag_zf', z3.BoolVal(False))
        old_sf = self.flag_state.get('flag_sf', z3.BoolVal(False))
        old_cf = self.flag_state.get('flag_cf', z3.BoolVal(False))
        old_of = self.flag_state.get('flag_of', z3.BoolVal(False))
        if 'flag_zf' in requested:
            new_zf = res_ast == 0
            self._write_flag('flag_zf', z3.If(shift_count == 0, old_zf, new_zf))
        if 'flag_sf' in requested:
            new_sf = z3.Extract(dst_size - 1, dst_size - 1, res_ast) == 1
            self._write_flag('flag_sf', z3.If(shift_count == 0, old_sf, new_sf))
        new_cf = None
        if 'flag_cf' in requested or 'flag_of' in requested:
            one_ast = z3.BitVecVal(1, dst_size)
            if mnemonic == 'shl':
                shifted_minus_one = z3.If(shift_count == 0, dst_val, dst_val << shift_count - one_ast)
                new_cf = z3.LShR(shifted_minus_one, dst_size - 1) & 1 == 1
            elif mnemonic in ['shr', 'sar']:
                shifted_minus_one = z3.If(shift_count == 0, dst_val, z3.LShR(dst_val, shift_count - one_ast))
                new_cf = shifted_minus_one & 1 == 1
            if 'flag_cf' in requested:
                self._write_flag('flag_cf', z3.If(shift_count == 0, old_cf, new_cf))
        if 'flag_of' in requested:
            if mnemonic == 'shl':
                msb_res = z3.Extract(dst_size - 1, dst_size - 1, res_ast) == 1
                new_of = msb_res != new_cf
            elif mnemonic == 'shr':
                new_of = z3.Extract(dst_size - 1, dst_size - 1, dst_val) == 1
            elif mnemonic == 'sar':
                new_of = z3.BoolVal(False)
            undef_of = z3.Bool(self._get_new_ssa_name('flag_of_undef'))
            self._write_flag('flag_of', z3.If(shift_count == 0, old_of, z3.If(shift_count == 1, new_of, undef_of)))

    def _read_operand(self, op_dict: dict) -> Tuple[z3.BitVecRef, int]:
        op_type = op_dict['type']
        if op_type == 'imm':
            size = op_dict.get('size', 8) * 8
            val = op_dict['value']
            if val < 0:
                val = (1 << size) + val
            return (z3.BitVecVal(val, size), size)
        if op_type == 'reg':
            op_str = op_dict['value']
            size = op_dict.get('size', 8) * 8
            base_reg = self._reg_to_base.get(op_str, op_str)
            offset = 8 if op_str.endswith('h') and len(op_str) == 2 else 0
            phys_val = self._get_phys_reg(base_reg)
            extracted = z3.Extract(offset + size - 1, offset, phys_val)
            return (extracted, size)
        if op_type == 'mem':
            addr_ast = z3.BitVecVal(op_dict['disp'], 64)
            if op_dict['base']:
                base_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['base'], 'size': 8})
                if base_ast.size() != 64:
                    base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                addr_ast = addr_ast + base_ast
            if op_dict['index']:
                index_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['index'], 'size': 8})
                if index_ast.size() != 64:
                    index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                addr_ast = addr_ast + index_ast * op_dict['scale']
            size = op_dict.get('size', 8) * 8
            if size == 0:
                size = 64
            read_bytes = []
            simplified_addr = self._safe_simplify(addr_ast)
            is_concrete_addr = isinstance(simplified_addr, z3.BitVecNumRef)
            concrete_addr_val = simplified_addr.as_long() if is_concrete_addr else 0
            is_tainted_addr = self._is_tainted(addr_ast)
            if not is_concrete_addr and (not is_tainted_addr) and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_read:
                concrete_addr_val = self.current_instr.mem_read[0]
                addr_ast = z3.BitVecVal(concrete_addr_val, 64)
                is_concrete_addr = True
            elif is_tainted_addr:
                self.solver.add(z3.UGE(addr_ast, 65536), z3.ULE(addr_ast, 140737488355327))
            for i in range(size // 8):
                byte_addr = self._safe_simplify(addr_ast + i)
                byte_ast = None
                
                # 1. Fast Path: Concrete memory address
                if is_concrete_addr:
                    c_addr = concrete_addr_val + i
                    if c_addr in self.concrete_memory:
                        byte_ast = self.concrete_memory[c_addr]
                    elif self.memory_provider:
                        try:
                            concrete_byte = self.memory_provider(c_addr, 1)
                            if concrete_byte:
                                byte_val = int.from_bytes(concrete_byte, byteorder='little')
                                byte_ast = z3.BitVecVal(byte_val, 8)
                                if i == 0:
                                    print(f'  -> [Smart Concretization] Resolved static memory at {hex(concrete_addr_val)} (Size: {size} bits)')
                        except Exception:
                            pass
                elif isinstance(byte_addr, z3.BitVecNumRef):
                    c_addr = byte_addr.as_long()
                    if c_addr in self.concrete_memory:
                        byte_ast = self.concrete_memory[c_addr]
                    elif self.memory_provider:
                        try:
                            concrete_byte = self.memory_provider(c_addr, 1)
                            if concrete_byte:
                                byte_val = int.from_bytes(concrete_byte, byteorder='little')
                                byte_ast = z3.BitVecVal(byte_val, 8)
                                if i == 0:
                                    print(f'  -> [Smart Concretization] Resolved static memory at {hex(c_addr)} (Size: {size} bits)')
                        except Exception:
                            pass
                
                # 2. Symbolic Path: Only if address is symbolic or not found in concrete stores
                if byte_ast is None:
                    chain = []
                    for write_addr_ast, write_byte_ast, write_size in reversed(self.memory_writes):
                        cond = byte_addr == write_addr_ast
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
                            simp_cond = self._safe_simplify(cond)
                            if z3.is_true(simp_cond):
                                is_t = True
                            elif z3.is_false(simp_cond):
                                is_f = True

                        if is_t:
                            chain.append((True, write_byte_ast))
                            break
                        elif is_f:
                            continue
                        else:
                            chain.append((cond, write_byte_ast))
                    if not chain or chain[-1][0] is not True:
                        tick = self.current_instr.tick if self.current_instr else 0
                        mem_name = f'SymMemRead_{self.mem_read_idx}_t{tick}_b{i}'
                        self.mem_read_idx += 1
                        byte_ast = z3.BitVec(mem_name, 8)
                        if i == 0:
                            print(f'  -> [Symbolic Memory] Falling back to unknown for symbolic address at Tick {tick}')
                    else:
                        byte_ast = chain.pop()[1]
                    while chain:
                        cond, val = chain.pop()
                        byte_ast = z3.If(cond, val, byte_ast)
                read_bytes.append(byte_ast)
            if len(read_bytes) == 1:
                result_ast = read_bytes[0]
            else:
                result_ast = z3.Concat(*reversed(read_bytes))
            return (result_ast, size)
        return (z3.BitVecVal(0, 64), 64)

    def _is_concrete_tree(self, ast, memo=None):
        if memo is None:
            memo = {}
        ast_id = ast.get_id()
        if ast_id in memo:
            return memo[ast_id]
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
        if op_type == 'reg':
            op_str = op_dict['value']
            reg_size = op_dict.get('size', 8) * 8
            base_reg = self._reg_to_base.get(op_str, op_str)
            offset = 8 if op_str.endswith('h') and len(op_str) == 2 else 0
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
        if op_type == 'mem':
            write_addr_ast = z3.BitVecVal(op_dict['disp'], 64)
            if op_dict['base']:
                base_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['base'], 'size': 8})
                if base_ast.size() != 64:
                    base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                write_addr_ast = write_addr_ast + base_ast
            if op_dict['index']:
                index_ast, _ = self._read_operand({'type': 'reg', 'value': op_dict['index'], 'size': 8})
                if index_ast.size() != 64:
                    index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                write_addr_ast = write_addr_ast + index_ast * op_dict['scale']
            simplified_write_addr = self._safe_simplify(write_addr_ast)
            is_concrete_w = isinstance(simplified_write_addr, z3.BitVecNumRef)
            concrete_w_val = simplified_write_addr.as_long() if is_concrete_w else None
            is_tainted_addr = self._is_tainted(write_addr_ast)
            
            if not is_concrete_w and not is_tainted_addr and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_write:
                concrete_w_val = self.current_instr.mem_write[0]
                simplified_write_addr = z3.BitVecVal(concrete_w_val, 64)
                write_addr_ast = simplified_write_addr
                is_concrete_w = True
            elif is_tainted_addr:
                self.solver.add(z3.UGE(write_addr_ast, 65536), z3.ULE(write_addr_ast, 140737488355327))
                
            mem_size = op_dict.get('size', size // 8) * 8
            if mem_size == 0:
                mem_size = size
            val = native_val
            if val.size() > mem_size:
                val = z3.Extract(mem_size - 1, 0, val)
            elif val.size() < mem_size:
                val = z3.ZeroExt(mem_size - val.size(), val)
            for i in range(mem_size // 8):
                byte_val = z3.Extract(i * 8 + 7, i * 8, val)
                if is_concrete_w:
                    self.concrete_memory[concrete_w_val + i] = byte_val
                self.memory_writes.append((self._safe_simplify(write_addr_ast + i), byte_val, 8))
            return

    def _match_sizes(self, dst_val: z3.BitVecRef, src_val: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        d_size = dst_val.size()
        s_size = src_val.size()
        if d_size > s_size:
            src_val = z3.ZeroExt(d_size - s_size, src_val)
        elif s_size > d_size:
            src_val = z3.Extract(d_size - 1, 0, src_val)
        return (dst_val, src_val)

    def _handle_mov(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            dst, src = (ops[0], ops[1])
            _, dst_size = self._read_operand(dst)
            src_val, src_size = self._read_operand(src)
            if instr.mnemonic == 'movzx':
                src_val = z3.ZeroExt(dst_size - src_size, src_val) if dst_size > src_size else src_val
            elif instr.mnemonic in ['movsx', 'movsxd']:
                src_val = z3.SignExt(dst_size - src_size, src_val) if dst_size > src_size else src_val
            elif src_size > dst_size:
                src_val = z3.Extract(dst_size - 1, 0, src_val)
            elif src_size < dst_size:
                src_val = z3.ZeroExt(dst_size - src_size, src_val)
            self._write_operand(dst, src_val)

    def _handle_lea(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            dst, src = (ops[0], ops[1])
            if src['type'] == 'mem':
                addr_ast = z3.BitVecVal(src['disp'], 64)
                if src['base']:
                    base_ast, _ = self._read_operand({'type': 'reg', 'value': src['base']})
                    if base_ast.size() != 64:
                        base_ast = z3.ZeroExt(64 - base_ast.size(), base_ast)
                    addr_ast = addr_ast + base_ast
                if src['index']:
                    index_ast, _ = self._read_operand({'type': 'reg', 'value': src['index']})
                    if index_ast.size() != 64:
                        index_ast = z3.ZeroExt(64 - index_ast.size(), index_ast)
                    addr_ast = addr_ast + index_ast * src['scale']
                _, dst_size = self._read_operand(dst)
                if dst_size < 64:
                    addr_ast = z3.Extract(dst_size - 1, 0, addr_ast)
                self._write_operand(dst, addr_ast)

    def _handle_math(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            dst, src = (ops[0], ops[1])
            dst_val, dst_size = self._read_operand(dst)
            src_val, src_size = self._read_operand(src)
            dst_val, src_val = self._match_sizes(dst_val, src_val)
            if instr.mnemonic == 'add':
                res = dst_val + src_val
            elif instr.mnemonic in ['sub', 'cmp']:
                res = dst_val - src_val
            elif instr.mnemonic == 'xor':
                res = dst_val ^ src_val
            elif instr.mnemonic in ['and', 'test']:
                res = dst_val & src_val
            elif instr.mnemonic == 'or':
                res = dst_val | src_val
            if instr.mnemonic not in ['cmp', 'test']:
                self._write_operand(dst, res)
            self.generate_flags(instr, instr.mnemonic, dst_val, src_val, res, dst_size)

    def _handle_inc_dec(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            dst = ops[0]
            dst_val, dst_size = self._read_operand(dst)
            src_val = z3.BitVecVal(1, dst_size)
            if instr.mnemonic == 'inc':
                res = dst_val + src_val
            elif instr.mnemonic == 'dec':
                res = dst_val - src_val
            self._write_operand(dst, res)
            self.generate_flags(instr, instr.mnemonic, dst_val, src_val, res, dst_size)

    def _handle_shift(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            dst, src = (ops[0], ops[1])
            dst_val, dst_size = self._read_operand(dst)
            src_val, src_size = self._read_operand(src)
            dst_val, src_val = self._match_sizes(dst_val, src_val)
            mask_val = 63 if dst_size == 64 else 31
            shift_count = src_val & z3.BitVecVal(mask_val, dst_size)
            if instr.mnemonic == 'shl':
                res = dst_val << shift_count
            elif instr.mnemonic == 'shr':
                res = z3.LShR(dst_val, shift_count)
            elif instr.mnemonic == 'sar':
                res = dst_val >> shift_count
            self._write_operand(dst, res)
            self.generate_shift_flags(instr, instr.mnemonic, dst_val, dst_size, shift_count, res)

    def _handle_jcc(self, instr):
        ops = instr.operands
        if hasattr(instr, 'jump_taken') and instr.jump_taken is not None:
            zf = self.flag_state.get('flag_zf', z3.BoolVal(False))
            cf = self.flag_state.get('flag_cf', z3.BoolVal(False))
            sf = self.flag_state.get('flag_sf', z3.BoolVal(False))
            of = self.flag_state.get('flag_of', z3.BoolVal(False))
            cond_ast = None
            m = instr.mnemonic
            if m in ['je', 'jz']:
                cond_ast = zf
            elif m in ['jne', 'jnz']:
                cond_ast = z3.Not(zf)
            elif m in ['ja', 'jnbe']:
                cond_ast = z3.And(z3.Not(cf), z3.Not(zf))
            elif m in ['jae', 'jnb', 'jnc']:
                cond_ast = z3.Not(cf)
            elif m in ['jb', 'jc', 'jnae']:
                cond_ast = cf
            elif m in ['jbe', 'jna']:
                cond_ast = z3.Or(cf, zf)
            elif m in ['jg', 'jnle']:
                cond_ast = z3.And(z3.Not(zf), sf == of)
            elif m in ['jge', 'jnl']:
                cond_ast = sf == of
            elif m in ['jl', 'jnge']:
                cond_ast = sf != of
            elif m in ['jle', 'jng']:
                cond_ast = z3.Or(zf, sf != of)
            elif m in ['js']:
                cond_ast = sf
            elif m in ['jns']:
                cond_ast = z3.Not(sf)
            elif m in ['jo']:
                cond_ast = of
            elif m in ['jno']:
                cond_ast = z3.Not(of)
            if cond_ast is not None:
                self.last_jcc_cond_ast = cond_ast
                self.last_jcc_jump_taken = instr.jump_taken
                if instr.jump_taken:
                    print(f"  -> [OK] [Z3 Jump Taken] Added Constraint for {instr.mnemonic} at Tick {instr.tick}")
                    self.solver.add(cond_ast)
                else:
                    print(f"  -> [OK] [Z3 Jump Not Taken] Added Constraint for {instr.mnemonic} at Tick {instr.tick}")
                    self.solver.add(z3.Not(cond_ast))

    def _handle_mul(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            src = ops[0]
            src_val, src_size = self._read_operand(src)
            if src_size == 8:
                implied_val, _ = self._read_operand({'type': 'reg', 'value': 'al', 'size': 1})
            elif src_size == 16:
                implied_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
            elif src_size == 32:
                implied_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
            elif src_size == 64:
                implied_val, _ = self._read_operand({'type': 'reg', 'value': 'rax', 'size': 8})
            else:
                return
            if instr.mnemonic == 'mul':
                expanded_src = z3.ZeroExt(src_size, src_val)
                expanded_impl = z3.ZeroExt(src_size, implied_val)
            else:
                expanded_src = z3.SignExt(src_size, src_val)
                expanded_impl = z3.SignExt(src_size, implied_val)
            result_math = expanded_src * expanded_impl
            if src_size == 8:
                self._write_operand({'type': 'reg', 'value': 'ax', 'size': 2}, result_math)
            else:
                lower_half = z3.Extract(src_size - 1, 0, result_math)
                upper_half = z3.Extract(src_size * 2 - 1, src_size, result_math)
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
            src2 = ops[2] if len(ops) == 3 else ops[0]
            dst_val, dst_size = self._read_operand(dst)
            src1_val, _ = self._read_operand(src1)
            src2_val, _ = self._read_operand(src2)
            if src1_val.size() < dst_size:
                src1_val = z3.SignExt(dst_size - src1_val.size(), src1_val)
            elif src1_val.size() > dst_size:
                src1_val = z3.Extract(dst_size - 1, 0, src1_val)
            if src2_val.size() < dst_size:
                src2_val = z3.SignExt(dst_size - src2_val.size(), src2_val)
            elif src2_val.size() > dst_size:
                src2_val = z3.Extract(dst_size - 1, 0, src2_val)
            res = src1_val * src2_val
            self._write_operand(dst, res)

    def _handle_push(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            src = ops[0]
            src_val, src_size = self._read_operand(src)
            rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
            if not self._is_tainted(rsp_val) and hasattr(instr, 'mem_write') and instr.mem_write:
                rsp_new = z3.BitVecVal(instr.mem_write[0], 64)
            else:
                rsp_new = rsp_val - src_size // 8
            self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
            simplified_rsp = self._safe_simplify(rsp_new)
            is_concrete_rsp = isinstance(simplified_rsp, z3.BitVecNumRef)
            c_rsp = simplified_rsp.as_long() if is_concrete_rsp else None
            for i in range(src_size // 8):
                byte_val = z3.Extract(i * 8 + 7, i * 8, src_val)
                if is_concrete_rsp:
                    self.concrete_memory[c_rsp + i] = byte_val
                self.memory_writes.append((self._safe_simplify(rsp_new + i), byte_val, 8))

    def _handle_pop(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            dst = ops[0]
            _, dst_size = self._read_operand(dst)
            res_val, _ = self._read_operand({'type': 'mem', 'disp': 0, 'base': 'rsp', 'index': None, 'scale': 1, 'size': dst_size // 8})
            self._write_operand(dst, res_val)
            rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
            if not self._is_tainted(rsp_val) and hasattr(instr, 'mem_read') and instr.mem_read:
                rsp_new = z3.BitVecVal(instr.mem_read[0] + dst_size // 8, 64)
            else:
                rsp_new = rsp_val + dst_size // 8
            self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)

    def _handle_cbw(self, instr):
        al_val, _ = self._read_operand({'type': 'reg', 'value': 'al', 'size': 1})
        ax_val = z3.SignExt(8, al_val)
        self._write_operand({'type': 'reg', 'value': 'ax', 'size': 2}, ax_val)

    def _handle_cwde(self, instr):
        ax_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
        eax_val = z3.SignExt(16, ax_val)
        self._write_operand({'type': 'reg', 'value': 'eax', 'size': 4}, eax_val)

    def _handle_cdqe(self, instr):
        eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
        rax_val = z3.SignExt(32, eax_val)
        self._write_operand({'type': 'reg', 'value': 'rax', 'size': 8}, rax_val)

    def _handle_cwd(self, instr):
        ax_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
        ext = z3.SignExt(16, ax_val)
        dx_val = z3.Extract(31, 16, ext)
        self._write_operand({'type': 'reg', 'value': 'dx', 'size': 2}, dx_val)

    def _handle_cdq(self, instr):
        eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
        ext = z3.SignExt(32, eax_val)
        edx_val = z3.Extract(63, 32, ext)
        self._write_operand({'type': 'reg', 'value': 'edx', 'size': 4}, edx_val)

    def _handle_cqo(self, instr):
        rax_val, _ = self._read_operand({'type': 'reg', 'value': 'rax', 'size': 8})
        ext = z3.SignExt(64, rax_val)
        rdx_val = z3.Extract(127, 64, ext)
        self._write_operand({'type': 'reg', 'value': 'rdx', 'size': 8}, rdx_val)

    def _handle_setcc(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            dst = ops[0]

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
            if m in ['sete', 'setz']:
                cond_ast = zf
            elif m in ['setne', 'setnz']:
                cond_ast = z3.Not(zf)
            elif m in ['seta', 'setnbe']:
                cond_ast = z3.And(z3.Not(cf), z3.Not(zf))
            elif m in ['setae', 'setnb', 'setnc']:
                cond_ast = z3.Not(cf)
            elif m in ['setb', 'setc', 'setnae']:
                cond_ast = cf
            elif m in ['setbe', 'setna']:
                cond_ast = z3.Or(cf, zf)
            elif m in ['setg', 'setnle']:
                cond_ast = z3.And(z3.Not(zf), sf == of)
            elif m in ['setge', 'setnl']:
                cond_ast = sf == of
            elif m in ['setl', 'setnge']:
                cond_ast = sf != of
            elif m in ['setle', 'setng']:
                cond_ast = z3.Or(zf, sf != of)
            elif m in ['sets']:
                cond_ast = sf
            elif m in ['setns']:
                cond_ast = z3.Not(sf)
            elif m in ['seto']:
                cond_ast = of
            elif m in ['setno']:
                cond_ast = z3.Not(of)
            if cond_ast is not None:
                res_val = z3.If(cond_ast, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
                self._write_operand(dst, res_val)

    def _handle_jmp(self, instr):
        ops = instr.operands
        pass

    def _handle_call(self, instr):
        ops = instr.operands
        rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
        if hasattr(instr, 'mem_write') and instr.mem_write:
            rsp_new = z3.BitVecVal(instr.mem_write[0], 64)
        else:
            rsp_new = rsp_val - 8
        self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)
        rip_val = z3.BitVecVal(instr.address + instr.size, 64)
        simplified_rsp = self._safe_simplify(rsp_new)
        is_concrete_rsp = isinstance(simplified_rsp, z3.BitVecNumRef)
        c_rsp = simplified_rsp.as_long() if is_concrete_rsp else None
        for i in range(8):
            byte_val = z3.Extract(i * 8 + 7, i * 8, rip_val)
            if is_concrete_rsp:
                self.concrete_memory[c_rsp + i] = byte_val
            self.memory_writes.append((self._safe_simplify(rsp_new + i), byte_val, 8))
        is_external = False
        if 'rax' in instr.regs_write:
            is_external = True
        if is_external:
            print(f'  -> [Clobber] Call to external API at Tick {instr.tick}. Clobbering volatile registers.')
            for r in ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']:
                self._clobber_register(r)

    def _handle_ret(self, instr):
        ops = instr.operands
        rsp_val, _ = self._read_operand({'type': 'reg', 'value': 'rsp', 'size': 8})
        rsp_new = rsp_val + 8
        if len(ops) == 1:
            imm = ops[0]
            if imm['type'] == 'imm':
                rsp_new = rsp_new + imm['value']
        self._write_operand({'type': 'reg', 'value': 'rsp', 'size': 8}, rsp_new)

    def _handle_cmpxchg(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            dst, src = (ops[0], ops[1])
            dst_val, dst_size = self._read_operand(dst)
            src_val, src_size = self._read_operand(src)
            acc_reg = 'al'
            if dst_size == 16:
                acc_reg = 'ax'
            elif dst_size == 32:
                acc_reg = 'eax'
            elif dst_size == 64:
                acc_reg = 'rax'
            acc_val, _ = self._read_operand({'type': 'reg', 'value': acc_reg})
            dst_val, src_val = self._match_sizes(dst_val, src_val)
            acc_val, dst_val = self._match_sizes(acc_val, dst_val)
            is_eq = False
            if dst['type'] == 'mem':
                is_eq = len(instr.mem_write) > 0
            if is_eq:
                self.solver.add(acc_val == dst_val)
                self._write_operand(dst, src_val)
                self._write_flag('flag_zf', z3.BoolVal(True))
            else:
                self.solver.add(acc_val != dst_val)
                self._write_operand({'type': 'reg', 'value': acc_reg}, dst_val)
                self._write_flag('flag_zf', z3.BoolVal(False))

    def _handle_xchg(self, instr):
        ops = instr.operands
        if len(ops) == 2:
            op1, op2 = (ops[0], ops[1])
            val1, size1 = self._read_operand(op1)
            val2, size2 = self._read_operand(op2)
            val1, val2 = self._match_sizes(val1, val2)
            self._write_operand(op1, val2)
            self._write_operand(op2, val1)

    def parse_instruction(self, instr: TraceRecord):
        self.current_instr = instr
        self.mem_read_idx = 0
        self.mem_write_idx = 0
        handler = self.handlers.get(instr.mnemonic)
        if handler:
            print(f"    [Z3Translator] Parsing {instr.mnemonic} {instr.op_str}")
            handler(instr)
        else:
            print(f"[!] Z3Translator WARNING: Unhandled instruction '{instr.mnemonic} {instr.op_str}' at Tick {instr.tick}. Mathematical state may be lost!")

    def translate_slice(self, slice_records: List):
        print('[+] Starting Z3 Translation Phase (Native Width Model)...')
        from asm_analyzer.engine.vsa_evaluator import LoopSummary
        chronological_slice = list(reversed(slice_records))
        for i, item in enumerate(chronological_slice):
            if isinstance(item, LoopSummary):
                self.translate_loop_summary(item, item.iterations)
            else:
                next_instr = chronological_slice[i + 1] if i + 1 < len(chronological_slice) else None
                self.parse_instruction(item)
        print('[+] Z3 Translation Complete. Assertions:')
        for assertion in self.solver.assertions():
            print(f'  {assertion}')

    def translate_loop_summary(self, summary, max_iterations: int):
        from asm_analyzer.engine.vsa_evaluator import LoopSummary
        if not isinstance(summary, LoopSummary):
            return

        # 1. Generate Unique Symbolic N per LoopBlock
        loop_tick = getattr(summary, 'tick', None)
        if loop_tick is not None:
            loop_var_name = f'LoopCounter_t{loop_tick}'
        else:
            loop_var_name = self._get_new_ssa_name('LoopCounter')
            
        N = z3.BitVec(loop_var_name, 64)
        summary.loop_counter_var = N
        self.latest_loop_counter = N
        
        # 2. Bound N (0 <= N <= 10,000,000)
        self.solver.add(z3.UGE(N, 0))
        self.solver.add(z3.ULE(N, 10000000))
        
        # 3. Optimize N (User's instruction: Minimize N to find the shortest path)
        if hasattr(self.solver, 'minimize'):
             self.solver.minimize(N)
        
        # Temporarily clear current_instr to prevent _write_operand from overriding addresses
        old_instr = getattr(self, 'current_instr', None)
        self.current_instr = None
        
        def _build_polycyclic_delta(N_var, pattern: List[int], bit_size: int = 64):
            P = len(pattern)
            P_val = z3.BitVecVal(P, bit_size)
            cycle_sum = sum(pattern)
            cycle_sum_val = z3.BitVecVal(cycle_sum, bit_size)
            
            Q = z3.UDiv(N_var, P_val)
            R = z3.URem(N_var, P_val)
            
            prefix = [0]
            for x in pattern:
                prefix.append(prefix[-1] + x)
                
            def build_prefix_if(R_ast, p_list, idx=1):
                if idx >= len(p_list) - 1:
                    return z3.BitVecVal(p_list[idx], bit_size)
                return z3.If(
                    R_ast == idx,
                    z3.BitVecVal(p_list[idx], bit_size),
                    build_prefix_if(R_ast, p_list, idx + 1)
                )
                
            extra_delta = z3.If(R == 0, z3.BitVecVal(0, bit_size), build_prefix_if(R, prefix, 1))
            return Q * cycle_sum_val + extra_delta
            
        shadow_subs = []
        composed_inner_deltas = {}
        
        # 3.1. Process Child Inner Loops Symbolically
        inner_summaries = getattr(summary, 'inner_summaries', [])
        if inner_summaries:
            print(f"  [Z3Translator] Found {len(inner_summaries)} Symbolic Child Inner Loop(s)!")
            for inner_sum in inner_summaries:
                inner_tick = getattr(inner_sum, 'tick', None)
                if inner_tick is not None:
                    inner_var_name = f'LoopCounter_t{inner_tick}'
                else:
                    inner_var_name = self._get_new_ssa_name('LoopCounter')
                    
                N_inner = z3.BitVec(inner_var_name, 64)
                inner_sum.loop_counter_var = N_inner
                self.solver.add(z3.UGE(N_inner, 0))
                self.solver.add(z3.ULE(N_inner, 10000000))
                
                # Apply inner delta to inner control variables (like loop counters)
                inner_shadow_subs = []
                for reg_name, delta in getattr(inner_sum, 'deltas', {}).items():
                    if reg_name.startswith("MEM_"):
                        parts = reg_name.split("_")
                        addr = int(parts[1])
                        size_bits = int(parts[2])
                        mem_op = {'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8}
                        # Induction variable for an inner loop within an outer loop body starts at 0 at each outer loop iteration
                        t_before = z3.BitVecVal(0, 64)
                        t_after = t_before + delta * N_inner if delta != 0 else t_before
                        t_after_extracted = z3.Extract(size_bits - 1, 0, t_after)
                        self._write_operand(mem_op, t_after_extracted)
                        t_after_shadow = z3.If(N_inner > 0, t_before + delta * (N_inner - 1), t_before)
                        t_after_shadow_extracted = z3.Extract(size_bits - 1, 0, t_after_shadow)
                        inner_shadow_subs.append((t_after_extracted, t_after_shadow_extracted))
                    else:
                        base_reg = self._reg_to_base.get(reg_name, reg_name)
                        t_before = z3.BitVecVal(0, 64)
                        self._clobber_register(base_reg)
                        t_after = self._get_phys_reg(base_reg)
                        if delta != 0:
                            self.solver.add(t_after == t_before + delta * N_inner)
                        else:
                            self.solver.add(t_after == t_before)
                        t_after_shadow = z3.If(N_inner > 0, t_before + delta * (N_inner - 1), t_before)
                        t_after_shadow_extracted = z3.Extract(t_after.size() - 1, 0, t_after_shadow)
                        inner_shadow_subs.append((t_after, t_after_shadow_extracted))
                        
                # Extract inner polycyclic pattern expressions for data flow
                for reg_name, pattern in getattr(inner_sum, 'patterns', {}).items():
                    d_expr = _build_polycyclic_delta(N_inner, pattern, 64)
                    composed_inner_deltas[reg_name] = d_expr
                    print(f"  [Z3Translator] Built Symbolic Inner Closed-Form Pattern for {reg_name} (Period P={len(pattern)})")
                    
                exit_cond_str = getattr(inner_sum, 'exit_condition', '') or ''
                for reg_name, delta in getattr(inner_sum, 'deltas', {}).items():
                    if reg_name not in composed_inner_deltas and reg_name not in exit_cond_str:
                        composed_inner_deltas[reg_name] = z3.BitVecVal(delta, 64) * N_inner
                        print(f"  [Z3Translator] Built Symbolic Inner Scalar Delta for {reg_name}: {delta} * {N_inner}")
                        
                # Translate inner exit condition to bind N_inner
                if getattr(inner_sum, 'exit_records', None):
                    self.last_jcc_cond_ast = None
                    self.last_jcc_jump_taken = None
                    for record in inner_sum.exit_records:
                        self.parse_instruction(record)
                    if self.last_jcc_cond_ast is not None and self.last_jcc_jump_taken is not None:
                        cond_shadow_ast = z3.substitute(self.last_jcc_cond_ast, *inner_shadow_subs)
                        expected_shadow_jump_taken = not self.last_jcc_jump_taken
                        iron_c = cond_shadow_ast if expected_shadow_jump_taken else z3.Not(cond_shadow_ast)
                        self.add_tracked_constraint(z3.Implies(N_inner > 0, iron_c), f"Inner Loop Exit Iron Constraint (t{inner_tick})")
                        print(f"  [Z3Translator] Inner Loop Exit Iron Constraint successfully injected for N_inner={N_inner}!")

        # 4. Apply Scalar Strides: Reg_new = Reg_old + Delta * N
        print(f"  [Z3Translator] Loop Summary Deltas: {summary.deltas}")
        for reg_name, delta in summary.deltas.items():
            if reg_name in composed_inner_deltas:
                step_delta = composed_inner_deltas[reg_name]
                if reg_name.startswith("MEM_"):
                    parts = reg_name.split("_")
                    addr = int(parts[1])
                    size_bits = int(parts[2])
                    t_before, _ = self._read_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8})
                    if t_before.size() != 64: t_before = z3.ZeroExt(64 - t_before.size(), t_before)
                    t_after = t_before + step_delta * N
                    
                    t_after_extracted = z3.Extract(size_bits - 1, 0, t_after)
                    self._write_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8}, t_after_extracted)
                    
                    t_after_shadow = z3.If(N > 0, t_before + step_delta * (N - 1), t_before)
                    t_after_shadow_extracted = z3.Extract(size_bits - 1, 0, t_after_shadow)
                    shadow_subs.append((t_after_extracted, t_after_shadow_extracted))
                    continue
                    
                base_reg = self._reg_to_base.get(reg_name, reg_name)
                t_before = self._get_phys_reg(base_reg)
                self._clobber_register(base_reg)
                t_after = self._get_phys_reg(base_reg)
                self.solver.add(t_after == t_before + step_delta * N)
                t_after_shadow = z3.If(N > 0, t_before + step_delta * (N - 1), t_before)
                t_after_shadow_extracted = z3.Extract(t_after.size() - 1, 0, t_after_shadow)
                shadow_subs.append((t_after, t_after_shadow_extracted))
                continue
                
            direct_delta = summary.direct_deltas.get(reg_name, delta)
            if reg_name.startswith("MEM_"):
                parts = reg_name.split("_")
                addr = int(parts[1])
                size_bits = int(parts[2])
                t_before, _ = self._read_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8})
                if t_before.size() != 64: t_before = z3.ZeroExt(64 - t_before.size(), t_before)
                t_after = t_before + direct_delta * N if direct_delta != 0 else t_before
                
                t_after_extracted = z3.Extract(size_bits - 1, 0, t_after)
                self._write_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8}, t_after_extracted)
                
                t_after_shadow = z3.If(N > 0, t_before + direct_delta * (N - 1), t_before)
                t_after_shadow_extracted = z3.Extract(size_bits - 1, 0, t_after_shadow)
                shadow_subs.append((t_after_extracted, t_after_shadow_extracted))
                continue
                
            base_reg = self._reg_to_base.get(reg_name, reg_name)
            t_before = self._get_phys_reg(base_reg)
            
            # Clobber and assert Loop Equation
            self._clobber_register(base_reg)
            t_after = self._get_phys_reg(base_reg)
            
            if direct_delta != 0:
                self.solver.add(t_after == t_before + direct_delta * N)
            else:
                self.solver.add(t_after == t_before)
                
            t_after_shadow = z3.If(N > 0, t_before + direct_delta * (N - 1), t_before)
            t_after_shadow_extracted = z3.Extract(t_after.size() - 1, 0, t_after_shadow)
            shadow_subs.append((t_after, t_after_shadow_extracted))

        # 5. Apply Polycyclic Patterns (Closed-Form Formula: Total = Q * Sum + Remainder_Prefix[R])
        patterns = getattr(summary, 'patterns', {})
        if patterns:
            print(f"  [Z3Translator] Loop Summary Polycyclic Patterns: {patterns}")
            N_prev = z3.If(N > 0, N - 1, z3.BitVecVal(0, 64))
            for reg_name, pattern in patterns.items():
                if reg_name in composed_inner_deltas:
                    continue
                total_delta = _build_polycyclic_delta(N, pattern, 64)
                total_delta_prev = _build_polycyclic_delta(N_prev, pattern, 64)
                
                if reg_name.startswith("MEM_"):
                    parts = reg_name.split("_")
                    addr = int(parts[1])
                    size_bits = int(parts[2])
                    t_before, _ = self._read_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8})
                    if t_before.size() != 64: t_before = z3.ZeroExt(64 - t_before.size(), t_before)
                    t_after = t_before + total_delta
                    
                    t_after_extracted = z3.Extract(size_bits - 1, 0, t_after)
                    self._write_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8}, t_after_extracted)
                    
                    t_after_shadow = z3.If(N > 0, t_before + total_delta_prev, t_before)
                    t_after_shadow_extracted = z3.Extract(size_bits - 1, 0, t_after_shadow)
                    shadow_subs.append((t_after_extracted, t_after_shadow_extracted))
                    continue
                    
                base_reg = self._reg_to_base.get(reg_name, reg_name)
                t_before = self._get_phys_reg(base_reg)
                
                self._clobber_register(base_reg)
                t_after = self._get_phys_reg(base_reg)
                
                self.solver.add(t_after == t_before + total_delta)
                
                t_after_shadow = z3.If(N > 0, t_before + total_delta_prev, t_before)
                t_after_shadow_extracted = z3.Extract(t_after.size() - 1, 0, t_after_shadow)
                shadow_subs.append((t_after, t_after_shadow_extracted))

        # 6. Handle Constant Sets from Loop body
        print(f"  [Z3Translator] Loop Summary Constant Sets: {summary.constant_sets}")
        for reg_name, const_val in summary.constant_sets.items():
            if reg_name.startswith("MEM_"):
                parts = reg_name.split("_")
                addr = int(parts[1])
                size_bits = int(parts[2])
                const_ast = z3.BitVecVal(const_val, size_bits)
                self._write_operand({'type': 'mem', 'disp': addr, 'base': None, 'index': None, 'scale': 1, 'size': size_bits // 8}, const_ast)
                continue
                
            base_reg = self._reg_to_base.get(reg_name, reg_name)
            self._clobber_register(base_reg)
            new_reg = self._get_phys_reg(base_reg)
            self.solver.add(new_reg == const_val)
            
        # Restore current_instr
        self.current_instr = old_instr
            
        # 7. Apply Exit Condition via SSA!
        # By translating the exit records, Z3 automatically uses the updated SSA registers 
        # (e.g. ecx_t1, edx_t0) to create the link between LoopCounter and the tainted variables!
        if hasattr(summary, 'exit_records') and summary.exit_records:
            self.last_jcc_cond_ast = None
            self.last_jcc_jump_taken = None
            
            for record in summary.exit_records:
                self.parse_instruction(record)
                
            if self.last_jcc_cond_ast is not None and self.last_jcc_jump_taken is not None:
                print(f"  [Z3Translator] Applying N-1 Iron Constraint!")
                
                cond_shadow_ast = z3.substitute(self.last_jcc_cond_ast, *shadow_subs)
                
                # The jump taken status at N-1 MUST be the OPPOSITE of what it was at N.
                expected_shadow_jump_taken = not self.last_jcc_jump_taken
                
                if expected_shadow_jump_taken:
                    iron_constraint = cond_shadow_ast
                else:
                    iron_constraint = z3.Not(cond_shadow_ast)
                    
                self.add_tracked_constraint(z3.Implies(N > 0, iron_constraint), f"Outer Loop Exit Iron Constraint (t{loop_tick})")
                print("  -> [OK] Loop exit equation successfully built and injected into solver.")

    def add_tracked_constraint(self, constraint: z3.BoolRef, label: str):
        """
        Adds a critical semantic constraint (e.g. Loop Equation, Exit Bound, Target Goal)
        with a human-readable label for fast, pinpoint Unsat Core diagnosis.
        """
        self.solver.add(constraint)
        tracker_name = f"tracker_{len(self.tracked_constraints)}_{re.sub(r'[^a-zA-Z0-9_]', '_', label)}"
        self.tracked_constraints[tracker_name] = (constraint, label)

    def explain_unsat(self) -> List[str]:
        """
        Fast, high-level Unsat Core diagnostics focusing specifically on 
        Loop Equations, Loop Exits, Key Bounds, and Goal Target constraints.
        """
        # 1. If tracked_constraints exist, run fast targeted check
        if self.tracked_constraints:
            solver = z3.Solver()
            tracked_exprs = {c[0] for c in self.tracked_constraints.values()}
            for assertion in self.solver.assertions():
                if assertion not in tracked_exprs:
                    solver.add(assertion)
                    
            tracker_vars = []
            named_trackers = {}
            for tracker_name, (constraint, label) in self.tracked_constraints.items():
                p = z3.Bool(tracker_name)
                solver.add(z3.Implies(p, constraint))
                tracker_vars.append(p)
                named_trackers[str(p)] = (label, constraint)
                
            print("\n[*] Running Fast Targeted Unsat Core Diagnostics on Loop & Semantic Constraints...")
            if solver.check(tracker_vars) == z3.unsat:
                core = solver.unsat_core()
                results = []
                print(f"\n[!] ==================== UNSAT CORE DIAGNOSTICS ====================")
                print(f"[!] Found {len(core)} conflicting semantic constraints in Z3:")
                for p in core:
                    label, expr = named_trackers[str(p)]
                    msg = f"  -> [{label}]: {expr}"
                    print(msg)
                    results.append(msg)
                print(f"[!] ==================================================================")
                return results

        # 2. Fallback: Check full assertion core
        print("\n[*] Checking full assertion Unsat Core in Z3...")
        fallback_solver = z3.Solver()
        full_named = {}
        full_trackers = []
        for idx, assertion in enumerate(self.solver.assertions()):
            p = z3.Bool(f"ssa_p_{idx}")
            fallback_solver.add(z3.Implies(p, assertion))
            full_trackers.append(p)
            full_named[str(p)] = assertion
            
        if fallback_solver.check(full_trackers) == z3.unsat:
            core = fallback_solver.unsat_core()
            results = []
            print(f"\n[!] ==================== UNSAT CORE DIAGNOSTICS ====================")
            print(f"[!] Found {len(core)} conflicting mathematical assertions in Z3:")
            for p in core:
                ast_str = str(full_named[str(p)])
                if len(ast_str) > 150:
                    ast_str = ast_str[:150] + "..."
                msg = f"  -> {ast_str}"
                print(msg)
                results.append(msg)
            print(f"[!] ==================================================================")
            return results
        else:
            print("[*] All individual tracked assertions are mutually consistent (Unsat caused by optimization objective or timeout).")
            return []