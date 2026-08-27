import z3
import re
import logging
from typing import List, Dict, Tuple, Optional, Union
from strilight.engine.tracker import TraceRecord
from strilight.engine.x86_defs import REGISTER_HIERARCHY, PHYSICAL_REGS, REG_TO_BASE

logger = logging.getLogger("strilight.engine.translator")

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
            'movabs': self._handle_mov,
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
            'neg': self._handle_neg,
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
            'div': self._handle_div,
            'idiv': self._handle_div,

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
        base_tick = self.current_instr.tick if self.current_instr and hasattr(self.current_instr, 'tick') and self.current_instr.tick is not None else 0
        last_ver = self.latest_versions.get(name, -1)
        if base_tick > last_ver:
            new_ver = base_tick
        else:
            new_ver = last_ver + 1
        self.latest_versions[name] = new_ver
        return f'{name}_t{new_ver}'

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

    def get_register(self, reg_name: str) -> z3.BitVecRef:
        """Public helper to get the current symbolic Z3 BitVec representation of any register or subregister."""
        expr, _ = self._read_operand({'type': 'reg', 'value': reg_name.lower().strip()})
        return expr

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

    def load_memory(self, addr_ast: z3.BitVecRef, size_bits: int, tick: int = 0) -> z3.BitVecRef:
        """
        Direct low-level memory read primitive.
        Reads `size_bits` from `addr_ast` (concrete memory, memory_provider, or symbolic write history).
        """
        if addr_ast.size() != 64:
            addr_ast = z3.ZeroExt(64 - addr_ast.size(), addr_ast) if addr_ast.size() < 64 else z3.Extract(63, 0, addr_ast)
        if size_bits == 0:
            size_bits = 64
        simplified_addr = self._safe_simplify(addr_ast)
        is_concrete_addr = isinstance(simplified_addr, z3.BitVecNumRef)
        concrete_addr_val = simplified_addr.as_long() if is_concrete_addr else 0
        is_tainted_addr = self._is_tainted(addr_ast)

        if is_tainted_addr:
            self.solver.add(z3.UGE(addr_ast, 65536), z3.ULE(addr_ast, 140737488355327))

        read_bytes = []
        for i in range(size_bits // 8):
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
                                logger.debug("Resolved static memory at %s (Size: %d bits)", hex(concrete_addr_val), size_bits)
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
                                logger.debug("Resolved static memory at %s (Size: %d bits)", hex(c_addr), size_bits)
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
                    mem_name = f'SymMemRead_{self.mem_read_idx}_t{tick}_b{i}'
                    self.mem_read_idx += 1
                    byte_ast = z3.BitVec(mem_name, 8)
                    if i == 0:
                        logger.debug("Falling back to unknown for symbolic address at Tick %s", tick)
                else:
                    byte_ast = chain.pop()[1]
                while chain:
                    cond, val = chain.pop()
                    byte_ast = z3.If(cond, val, byte_ast)
            read_bytes.append(byte_ast)
        if len(read_bytes) == 1:
            return self._safe_simplify(read_bytes[0])
        elif len(read_bytes) > 1:
            return self._safe_simplify(z3.Concat(*reversed(read_bytes)))
        return z3.BitVecVal(0, size_bits)

    def store_memory(self, addr_ast: z3.BitVecRef, native_val: z3.BitVecRef, size_bits: int):
        """
        Direct low-level memory store primitive.
        Stores `size_bits` of `native_val` at `addr_ast` into concrete_memory and memory_writes.
        """
        if addr_ast.size() != 64:
            addr_ast = z3.ZeroExt(64 - addr_ast.size(), addr_ast) if addr_ast.size() < 64 else z3.Extract(63, 0, addr_ast)

        simplified_write_addr = self._safe_simplify(addr_ast)
        is_concrete_w = isinstance(simplified_write_addr, z3.BitVecNumRef)
        concrete_w_val = simplified_write_addr.as_long() if is_concrete_w else None
        is_tainted_addr = self._is_tainted(addr_ast)

        if is_tainted_addr:
            self.solver.add(z3.UGE(addr_ast, 65536), z3.ULE(addr_ast, 140737488355327))

        if size_bits == 0:
            size_bits = native_val.size()
        val = native_val
        if val.size() > size_bits:
            val = z3.Extract(size_bits - 1, 0, val)
        elif val.size() < size_bits:
            val = z3.ZeroExt(size_bits - val.size(), val)

        for i in range(size_bits // 8):
            byte_val = self._safe_simplify(z3.Extract(i * 8 + 7, i * 8, val))
            if is_concrete_w:
                self.concrete_memory[concrete_w_val + i] = byte_val
            self.memory_writes.append((self._safe_simplify(addr_ast + i), byte_val, 8))

    def set_register(self, reg_name: str, native_val: z3.BitVecRef, reg_size_bits: Optional[int] = None) -> z3.BitVecRef:
        """
        Direct low-level register assignment primitive.
        Handles subregister masking/merging, 32-bit zero-extension on x86_64, and SSA variable allocation.
        """
        op_str = reg_name.lower().strip()
        base_reg = self._reg_to_base.get(op_str, op_str)
        if reg_size_bits is None:
            reg_size_bits = native_val.size()
        offset = 8 if op_str.endswith('h') and len(op_str) == 2 else 0
        size = native_val.size()
        if size != reg_size_bits:
            if size > reg_size_bits:
                native_val = z3.Extract(reg_size_bits - 1, 0, native_val)
            else:
                native_val = z3.ZeroExt(reg_size_bits - size, native_val)
        old_phys_val = self._get_phys_reg(base_reg)
        if reg_size_bits == 32 and offset == 0:
            new_phys_val = z3.ZeroExt(32, native_val)
        else:
            parts = []
            if offset + reg_size_bits < 64:
                parts.append(z3.Extract(63, offset + reg_size_bits, old_phys_val))
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
        return self.reg_state[base_reg]

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

            simplified_addr = self._safe_simplify(addr_ast)
            is_concrete_addr = isinstance(simplified_addr, z3.BitVecNumRef)
            is_tainted_addr = self._is_tainted(addr_ast)
            if not is_concrete_addr and (not is_tainted_addr) and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_read:
                concrete_addr_val = self.current_instr.mem_read[0]
                addr_ast = z3.BitVecVal(concrete_addr_val, 64)

            tick = self.current_instr.tick if getattr(self, 'current_instr', None) else 0
            res_ast = self.load_memory(addr_ast, size, tick=tick)
            return (res_ast, size)
        return (z3.BitVecVal(0, 64), 64)

    def _is_concrete_tree(self, root_ast) -> bool:
        if not hasattr(root_ast, 'get_id'):
            return True
        if isinstance(root_ast, (int, z3.BitVecNumRef, z3.BoolRef)) and not z3.is_const(root_ast):
            return True
        if z3.is_const(root_ast):
            return False

        visited = set()
        stack = [root_ast]
        while stack:
            curr = stack.pop()
            if not hasattr(curr, 'get_id'):
                continue
            cid = curr.get_id()
            if cid in visited:
                continue
            visited.add(cid)
            if isinstance(curr, z3.BitVecNumRef):
                continue
            if z3.is_const(curr):
                return False
            for child in curr.children():
                stack.append(child)
        return True

    def _safe_simplify(self, ast):
        if self._is_concrete_tree(ast):
            return z3.simplify(ast)
        return ast

    def _write_operand(self, op_dict: dict, native_val: z3.BitVecRef):
        op_type = op_dict['type']
        size = native_val.size()
        if op_type == 'reg':
            reg_size = op_dict.get('size', 8) * 8
            self.set_register(op_dict['value'], native_val, reg_size)
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
            is_tainted_addr = self._is_tainted(write_addr_ast)
            if not is_concrete_w and not is_tainted_addr and hasattr(self, 'current_instr') and self.current_instr and self.current_instr.mem_write:
                concrete_w_val = self.current_instr.mem_write[0]
                write_addr_ast = z3.BitVecVal(concrete_w_val, 64)

            mem_size = op_dict.get('size', size // 8) * 8
            if mem_size == 0:
                mem_size = size
            self.store_memory(write_addr_ast, native_val, mem_size)
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

    def _handle_cbw(self, instr):
        al_val, _ = self._read_operand({'type': 'reg', 'value': 'al', 'size': 1})
        al_8 = z3.Extract(7, 0, al_val) if al_val.size() > 8 else al_val
        ax_val = z3.SignExt(8, al_8)
        self._write_operand({'type': 'reg', 'value': 'ax', 'size': 2}, ax_val)

    def _handle_cwde(self, instr):
        ax_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
        ax_16 = z3.Extract(15, 0, ax_val) if ax_val.size() > 16 else ax_val
        eax_val = z3.SignExt(16, ax_16)
        self._write_operand({'type': 'reg', 'value': 'eax', 'size': 4}, eax_val)

    def _handle_cdqe(self, instr):
        eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
        eax_32 = z3.Extract(31, 0, eax_val) if eax_val.size() > 32 else eax_val
        rax_val = z3.SignExt(32, eax_32)
        self._write_operand({'type': 'reg', 'value': 'rax', 'size': 8}, rax_val)

    def _handle_cwd(self, instr):
        ax_val, _ = self._read_operand({'type': 'reg', 'value': 'ax', 'size': 2})
        ax_16 = z3.Extract(15, 0, ax_val) if ax_val.size() > 16 else ax_val
        dx_val = z3.If(z3.Extract(15, 15, ax_16) == 1, z3.BitVecVal(0xFFFF, 16), z3.BitVecVal(0, 16))
        self._write_operand({'type': 'reg', 'value': 'dx', 'size': 2}, dx_val)

    def _handle_cdq(self, instr):
        eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax', 'size': 4})
        eax_32 = z3.Extract(31, 0, eax_val) if eax_val.size() > 32 else eax_val
        edx_val = z3.If(z3.Extract(31, 31, eax_32) == 1, z3.BitVecVal(0xFFFFFFFF, 32), z3.BitVecVal(0, 32))
        self._write_operand({'type': 'reg', 'value': 'edx', 'size': 4}, edx_val)

    def _handle_cqo(self, instr):
        rax_val, _ = self._read_operand({'type': 'reg', 'value': 'rax', 'size': 8})
        rax_64 = z3.Extract(63, 0, rax_val) if rax_val.size() > 64 else rax_val
        rdx_val = z3.If(z3.Extract(63, 63, rax_64) == 1, z3.BitVecVal(0xFFFFFFFFFFFFFFFF, 64), z3.BitVecVal(0, 64))
        self._write_operand({'type': 'reg', 'value': 'rdx', 'size': 8}, rdx_val)

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

    def _handle_neg(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            dst = ops[0]
            dst_val, dst_size = self._read_operand(dst)
            res = -dst_val
            self._write_operand(dst, res)
            zero_val = z3.BitVecVal(0, dst_size)
            self.generate_flags(instr, 'sub', zero_val, dst_val, res, dst_size)

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

    def _handle_div(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            src = ops[0]
            src_val, src_size = self._read_operand(src)
            is_signed = (instr.mnemonic == 'idiv')
            if src_size == 32:
                eax_val, _ = self._read_operand({'type': 'reg', 'value': 'eax'})
                edx_val, _ = self._read_operand({'type': 'reg', 'value': 'edx'})
                eax_32 = z3.Extract(31, 0, eax_val) if eax_val.size() > 32 else eax_val
                edx_32 = z3.Extract(31, 0, edx_val) if edx_val.size() > 32 else edx_val
                src_32 = z3.Extract(31, 0, src_val) if src_val.size() > 32 else src_val
                dividend = z3.Concat(edx_32, eax_32)
                divisor = z3.SignExt(32, src_32) if is_signed else z3.ZeroExt(32, src_32)
                quotient = (dividend / divisor) if is_signed else z3.UDiv(dividend, divisor)
                remainder = z3.SRem(dividend, divisor) if is_signed else z3.URem(dividend, divisor)
                self._write_operand({'type': 'reg', 'value': 'eax'}, z3.Extract(31, 0, quotient))
                self._write_operand({'type': 'reg', 'value': 'edx'}, z3.Extract(31, 0, remainder))
            elif src_size == 64:
                rax_val, _ = self._read_operand({'type': 'reg', 'value': 'rax'})
                rdx_val, _ = self._read_operand({'type': 'reg', 'value': 'rdx'})
                rax_64 = z3.Extract(63, 0, rax_val) if rax_val.size() > 64 else rax_val
                rdx_64 = z3.Extract(63, 0, rdx_val) if rdx_val.size() > 64 else rdx_val
                src_64 = z3.Extract(63, 0, src_val) if src_val.size() > 64 else src_val
                dividend = z3.Concat(rdx_64, rax_64)
                divisor = z3.SignExt(64, src_64) if is_signed else z3.ZeroExt(64, src_64)
                quotient = (dividend / divisor) if is_signed else z3.UDiv(dividend, divisor)
                remainder = z3.SRem(dividend, divisor) if is_signed else z3.URem(dividend, divisor)
                self._write_operand({'type': 'reg', 'value': 'rax'}, z3.Extract(63, 0, quotient))
                self._write_operand({'type': 'reg', 'value': 'rdx'}, z3.Extract(63, 0, remainder))

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
                if instr.jump_taken:
                    logger.debug("[Z3 Jump Taken] Added Constraint for %s at Tick %s", instr.mnemonic, instr.tick)
                    self.solver.add(cond_ast)
                else:
                    logger.debug("[Z3 Jump Not Taken] Added Constraint for %s at Tick %s", instr.mnemonic, instr.tick)
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
    def _handle_setcc(self, instr):
        ops = instr.operands
        if len(ops) == 1:
            dst = ops[0]

            def get_flag_warn(name):
                if name not in self.flag_state:
                    logger.warning("Flag '%s' missing for '%s' at Tick %s. Fallback to False (Missing info/Edge case not accounted for).", name, instr.mnemonic, instr.tick)
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
            logger.debug("Call to external API at Tick %s. Clobbering volatile registers.", instr.tick)
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
            logger.debug("Parsing %s %s", instr.mnemonic, instr.op_str)
            handler(instr)
        else:
            logger.warning("Unhandled instruction '%s %s' at Tick %s. Mathematical state may be lost!", instr.mnemonic, instr.op_str, instr.tick)

    def translate_slice(self, slice_records: List):
        logger.debug("Starting Z3 Translation Phase (Native Width Model)...")
        from strilight.engine.vsa import LoopSummary
        chronological_slice = list(reversed(slice_records))
        for i, item in enumerate(chronological_slice):
            if isinstance(item, LoopSummary):
                self.translate_loop_summary(item, item.iterations)
            else:
                self.parse_instruction(item)
        logger.debug("Z3 Translation Complete. Assertions:")
        for assertion in self.solver.assertions():
            logger.debug("  %s", assertion)

    def translate_loop_summary(self, summary, max_iterations: int):
        from strilight.engine.vsa import LoopSummary, LoopSMTTranslator
        if not isinstance(summary, LoopSummary):
            return

        old_instr = getattr(self, 'current_instr', None)
        self.current_instr = summary

        # 0. Read Formal Mathematical Invariant Contract from the Core Library
        contract = getattr(summary, 'invariant_contract', None)
        if contract is not None:
            logger.debug("Enforcing Loop Invariant Contract: %s", contract.get_exit_invariant_rule())

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

        # 3. Optimize N (Minimize N to find the shortest path)
        if hasattr(self.solver, 'minimize'):
            self.solver.minimize(N)

        composed_inner_deltas = {}
        N_prev = z3.If(N > 0, N - 1, z3.BitVecVal(0, 64))

        # 4. Value resolver for AST evaluation before loop mutations
        def _resolve_val_to_ast(val):
            if isinstance(val, int):
                return z3.BitVecVal(val, 64)
            elif isinstance(val, str):
                if val.isdigit() or (val.startswith('-') and val[1:].isdigit()):
                    return z3.BitVecVal(int(val), 64)
                elif val.startswith('0x') or val.startswith('-0x'):
                    return z3.BitVecVal(int(val, 16), 64)
                else:
                    base_r = self._reg_to_base.get(val, val)
                    ast = self._get_phys_reg(base_r)
                    if ast.size() != 64:
                        ast = z3.ZeroExt(64 - ast.size(), ast)
                    return ast
            elif isinstance(val, (z3.BitVecRef, z3.ExprRef)):
                if val.size() != 64:
                    return z3.ZeroExt(64 - val.size(), val)
                return val
            return None

        # 5. Process Child Inner Loops Symbolically via LoopSMTTranslator
        inner_summaries = getattr(summary, 'inner_summaries', [])
        for inner_sum in inner_summaries:
            inner_tick = getattr(inner_sum, 'tick', None)
            if inner_tick is not None:
                inner_var_name = f'LoopCounter_t{inner_tick}'
                N_inner = z3.BitVec(inner_var_name, 64)
                inner_sum.loop_counter_var = N_inner
                self.add_tracked_constraint(
                    z3.And(z3.UGE(N_inner, 0), z3.ULE(N_inner, 10000000)),
                    f"Inner Loop Bound (t{inner_tick})"
                )
                if hasattr(self.solver, 'minimize'):
                    self.solver.minimize(N_inner)

                N_inner_prev = z3.If(N_inner > 0, N_inner - 1, z3.BitVecVal(0, 64))

                # Build inner SMT updates and compose into composed_inner_deltas
                inner_updates = LoopSMTTranslator.translate_loop_summary_to_smt_updates(
                    summary=inner_sum,
                    N_ast=N_inner,
                    N_prev_ast=N_inner_prev,
                    get_phys_reg_fn=lambda r: self._get_phys_reg(self._reg_to_base.get(r, r)),
                    resolve_val_fn=_resolve_val_to_ast,
                )
                for upd in inner_updates:
                    if upd.delta_ast is not None:
                        composed_inner_deltas[upd.name] = upd.delta_ast

                # Extract inner polycyclic pattern expressions for data flow
                for reg_name, pattern in getattr(inner_sum, 'patterns', {}).items():
                    d_expr = LoopSMTTranslator.build_polycyclic_delta_ast(N_inner, pattern, 64)
                    composed_inner_deltas[reg_name] = d_expr
                    logger.debug("Built Symbolic Inner Closed-Form Pattern for %s (Period P=%d)", reg_name, len(pattern))

                exit_cond_str = getattr(inner_sum, 'exit_condition', '') or ''
                for reg_name, delta in getattr(inner_sum, 'deltas', {}).items():
                    if reg_name not in composed_inner_deltas and reg_name not in exit_cond_str:
                        composed_inner_deltas[reg_name] = z3.BitVecVal(delta, 64) * N_inner
                        logger.debug("Built Symbolic Inner Scalar Delta for %s: %s * %s", reg_name, delta, N_inner)

                # Evaluate pre-comparison slice instructions in exit_records to bind computed bounds (e.g. key % 10)
                if getattr(inner_sum, 'exit_records', None):
                    for r_instr in inner_sum.exit_records:
                        if hasattr(r_instr, 'mnemonic') and not r_instr.mnemonic.startswith('j') and r_instr.mnemonic not in ('cmp', 'test'):
                            self.parse_instruction(r_instr)

                # Translate inner exit condition via LoopSMTTranslator
                inner_exit_constraints = LoopSMTTranslator.build_loop_exit_constraints(
                    summary=inner_sum,
                    N_ast=N_inner,
                    N_prev_ast=N_inner_prev,
                    resolve_val_fn=_resolve_val_to_ast,
                    get_phys_reg_fn=lambda r: self._get_phys_reg(self._reg_to_base.get(r, r)),
                )
                for exit_c, label in inner_exit_constraints:
                    self.add_tracked_constraint(exit_c, f"Inner {label} (t{inner_tick})")

        # 6. Build SMT State Updates & Exit Constraints for Main Loop (Decoupled SMT-LIB2 Engine)
        if getattr(summary, 'exit_records', None):
            for r_instr in summary.exit_records:
                if hasattr(r_instr, 'mnemonic') and not r_instr.mnemonic.startswith('j') and r_instr.mnemonic not in ('cmp', 'test'):
                    self.parse_instruction(r_instr)

        smt_updates = LoopSMTTranslator.translate_loop_summary_to_smt_updates(
            summary=summary,
            N_ast=N,
            N_prev_ast=N_prev,
            get_phys_reg_fn=lambda r: self._get_phys_reg(self._reg_to_base.get(r, r)),
            resolve_val_fn=_resolve_val_to_ast,
            composed_inner_deltas=composed_inner_deltas,
        )

        exit_constraints = LoopSMTTranslator.build_loop_exit_constraints(
            summary=summary,
            N_ast=N,
            N_prev_ast=N_prev,
            resolve_val_fn=_resolve_val_to_ast,
            get_phys_reg_fn=lambda r: self._get_phys_reg(self._reg_to_base.get(r, r)),
        )
        for exit_c, label in exit_constraints:
            self.add_tracked_constraint(exit_c, f"{label} (t{loop_tick})")

        # 6. Apply SMT Updates to SSA Timeline and Machine State
        for upd in smt_updates:
            if upd.constant_val is not None:
                if upd.is_mem:
                    mem_addr_ast = z3.BitVecVal(upd.mem_addr, 64)
                    self.store_memory(mem_addr_ast, z3.BitVecVal(upd.constant_val, upd.mem_size_bits), upd.mem_size_bits)
                else:
                    base_reg = self._reg_to_base.get(upd.name, upd.name)
                    self._clobber_register(base_reg)
                    new_reg = self._get_phys_reg(base_reg)
                    self.add_tracked_constraint(new_reg == upd.constant_val, f"Loop Const Set {upd.name} = {upd.constant_val} (t{loop_tick})")
                continue

            if upd.delta_ast is not None:
                scale_n = upd.scale_ast if getattr(upd, 'scale_ast', None) is not None else z3.BitVecVal(1, 64)
                scale_prev = upd.scale_prev_ast if getattr(upd, 'scale_prev_ast', None) is not None else z3.BitVecVal(1, 64)

                if upd.is_mem:
                    mem_addr_ast = z3.BitVecVal(upd.mem_addr, 64)
                    t_before = self.load_memory(mem_addr_ast, upd.mem_size_bits)
                    if t_before.size() != 64:
                        t_before = z3.ZeroExt(64 - t_before.size(), t_before)
                    t_after = (scale_n * t_before) + upd.delta_ast
                    t_after_extracted = z3.Extract(upd.mem_size_bits - 1, 0, t_after)
                    self.store_memory(mem_addr_ast, t_after_extracted, upd.mem_size_bits)
                else:
                    base_reg = self._reg_to_base.get(upd.name, upd.name)
                    t_before = self._get_phys_reg(base_reg)
                    self._clobber_register(base_reg)
                    t_after = self._get_phys_reg(base_reg)
                    self.add_tracked_constraint(t_after == (scale_n * t_before) + upd.delta_ast, f"Loop Master Update {upd.name} (t{loop_tick})")

        self.current_instr = old_instr

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
                
            logger.info("Running Fast Targeted Unsat Core Diagnostics on Loop & Semantic Constraints...")
            if solver.check(tracker_vars) == z3.unsat:
                core = solver.unsat_core()
                results = []
                logger.warning("Found %d conflicting semantic constraints in Z3:", len(core))
                for p in core:
                    label, expr = named_trackers[str(p)]
                    msg = f"[{label}]: {expr}"
                    logger.warning("  -> %s", msg)
                    results.append(f"  -> [{label}]: {expr}")
                return results

        # 2. Fallback: Check full assertion core
        logger.info("Checking full assertion Unsat Core in Z3...")
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
            logger.warning("Found %d conflicting mathematical assertions in Z3:", len(core))
            for p in core:
                ast_str = str(full_named[str(p)])
                if len(ast_str) > 150:
                    ast_str = ast_str[:150] + "..."
                msg = f"  -> {ast_str}"
                logger.warning(msg)
                results.append(msg)
            return results
        else:
            logger.info("All individual tracked assertions are mutually consistent (Unsat caused by optimization objective or timeout).")
            return []
