import z3
import logging
from typing import Dict, List, Tuple, Optional, Any, Callable, Union

logger = logging.getLogger("strilight.engine.stack_engine")


class StackByteCell:
    """
    Represents a single 8-bit byte cell in the Shadow Stack.
    Maintains provenance metadata (origin instruction, timestamp tick, taint flag).
    """
    __slots__ = ('byte_ast', 'origin_instr', 'timestamp', 'is_tainted')

    def __init__(
        self,
        byte_ast: z3.BitVecRef,
        origin_instr: Optional[Any] = None,
        timestamp: int = 0,
        is_tainted: bool = False
    ):
        self.byte_ast = byte_ast
        self.origin_instr = origin_instr
        self.timestamp = timestamp
        self.is_tainted = is_tainted

    def __repr__(self) -> str:
        return f"<StackByteCell val={self.byte_ast} origin={self.origin_instr} t={self.timestamp} tainted={self.is_tainted}>"


class SymbolicStackEngine:
    """
    Dedicated Symbolic Stack Engine & Shadow Memory Simulator.
    Decouples byte-level physical x86-64 stack semantics, Little-Endian slicing/stitching,
    partial overlap handling, and provenance tracking from the high-level SMT solver.
    """

    def __init__(
        self,
        memory_provider: Optional[Callable[[int, int], bytes]] = None,
        is_tainted_fn: Optional[Callable[[Any], bool]] = None,
        safe_simplify_fn: Optional[Callable[[z3.ExprRef], z3.ExprRef]] = None,
    ):
        self.memory_provider = memory_provider
        self.is_tainted_fn = is_tainted_fn or (lambda x: False)
        self.safe_simplify_fn = safe_simplify_fn or (lambda x: z3.simplify(x) if hasattr(x, 'sort') else x)

        # Concrete address store: Dict[concrete_address_int, StackByteCell]
        self.cells: Dict[int, StackByteCell] = {}

        # Symbolic address writes log: List[Tuple[addr_ast, StackByteCell, size]]
        self.symbolic_writes: List[Tuple[z3.BitVecRef, StackByteCell, int]] = []

        self.mem_read_idx = 0

    def _safe_simplify(self, expr: z3.ExprRef) -> z3.ExprRef:
        try:
            return self.safe_simplify_fn(expr)
        except Exception:
            return expr

    def _to_64bit_addr(self, addr: Union[int, z3.BitVecRef]) -> z3.BitVecRef:
        if isinstance(addr, int):
            return z3.BitVecVal(addr, 64)
        if hasattr(addr, 'size'):
            if addr.size() < 64:
                return z3.ZeroExt(64 - addr.size(), addr)
            elif addr.size() > 64:
                return z3.Extract(63, 0, addr)
            return addr
        return z3.BitVecVal(0, 64)

    def _slice_val_to_bytes(self, val: Union[int, z3.BitVecRef], size_bytes: int) -> List[z3.BitVecRef]:
        """
        Slices a native value into `size_bytes` 8-bit BitVec ASTs in Little-Endian order.
        Index 0 is the least significant byte (LSB).
        """
        total_bits = size_bytes * 8
        if isinstance(val, int):
            val_ast = z3.BitVecVal(val, total_bits)
        elif isinstance(val, z3.BitVecRef):
            if val.size() < total_bits:
                val_ast = z3.ZeroExt(total_bits - val.size(), val)
            elif val.size() > total_bits:
                val_ast = z3.Extract(total_bits - 1, 0, val)
            else:
                val_ast = val
        else:
            val_ast = z3.BitVecVal(0, total_bits)

        byte_asts = []
        for i in range(size_bytes):
            b = self._safe_simplify(z3.Extract(i * 8 + 7, i * 8, val_ast))
            byte_asts.append(b)
        return byte_asts

    def _stitch_bytes_to_ast(self, byte_cells: List[Union[StackByteCell, z3.BitVecRef]], size_bytes: int) -> z3.BitVecRef:
        """
        Stitches Little-Endian byte cells into a single BitVec AST via z3.Concat.
        """
        if not byte_cells:
            return z3.BitVecVal(0, size_bytes * 8)
        
        raw_asts = []
        for c in byte_cells:
            ast = c.byte_ast if isinstance(c, StackByteCell) else c
            if hasattr(ast, 'size') and ast.size() != 8:
                ast = z3.Extract(7, 0, ast)
            raw_asts.append(ast)

        if len(raw_asts) == 1:
            return self._safe_simplify(raw_asts[0])
        return self._safe_simplify(z3.Concat(*reversed(raw_asts)))

    def write_bytes(self, addr_ast: z3.BitVecRef, cells: List[StackByteCell]) -> None:
        """
        Low-level primitive to write a list of StackByteCell objects starting at `addr_ast`.
        """
        addr_64 = self._to_64bit_addr(addr_ast)
        simp_addr = self._safe_simplify(addr_64)
        is_concrete = isinstance(simp_addr, z3.BitVecNumRef)
        concrete_base = simp_addr.as_long() if is_concrete else None

        for i, cell in enumerate(cells):
            byte_addr = self._safe_simplify(addr_64 + i)
            if is_concrete and concrete_base is not None:
                self.cells[concrete_base + i] = cell
            self.symbolic_writes.append((byte_addr, cell, 8))

    def write_val(
        self,
        addr_ast: Union[int, z3.BitVecRef],
        val_ast: Union[int, z3.BitVecRef],
        size_bytes: int,
        origin_instr: Optional[Any] = None,
        timestamp: int = 0,
        is_tainted: bool = False
    ) -> None:
        """
        Writes `size_bytes` of `val_ast` to `addr_ast` with Little-Endian packing and metadata.
        """
        if size_bytes <= 0:
            size_bytes = 8
        byte_asts = self._slice_val_to_bytes(val_ast, size_bytes)
        cells = [
            StackByteCell(
                byte_ast=b,
                origin_instr=origin_instr,
                timestamp=timestamp,
                is_tainted=is_tainted
            )
            for b in byte_asts
        ]
        self.write_bytes(self._to_64bit_addr(addr_ast), cells)

    def read_bytes(
        self,
        addr_ast: Union[int, z3.BitVecRef],
        size_bytes: int,
        tick: int = 0
    ) -> Tuple[List[StackByteCell], z3.BitVecRef]:
        """
        Reads `size_bytes` starting at `addr_ast`.
        Resolves via:
        1. Concrete memory / cells cache.
        2. memory_provider (static/emulated binary snapshot).
        3. Symbolic writes history with conditional if-chaining.
        4. Fresh symbolic BitVec fallback.
        Returns `(list_of_StackByteCells, stitched_BitVecRef)`.
        """
        if size_bytes <= 0:
            size_bytes = 8
        addr_64 = self._to_64bit_addr(addr_ast)
        simp_addr = self._safe_simplify(addr_64)
        is_concrete = isinstance(simp_addr, z3.BitVecNumRef)
        concrete_base = simp_addr.as_long() if is_concrete else None

        read_cells: List[StackByteCell] = []

        for i in range(size_bytes):
            byte_addr = self._safe_simplify(addr_64 + i)
            cell: Optional[StackByteCell] = None

            # 1. Fast Path: Known concrete address in cells cache
            if is_concrete and concrete_base is not None:
                c_addr = concrete_base + i
                if c_addr in self.cells:
                    cell = self.cells[c_addr]
                elif self.memory_provider:
                    try:
                        raw_byte = self.memory_provider(c_addr, 1)
                        if raw_byte:
                            byte_val = int.from_bytes(raw_byte, byteorder='little')
                            cell = StackByteCell(
                                byte_ast=z3.BitVecVal(byte_val, 8),
                                origin_instr='static_memory',
                                timestamp=0,
                                is_tainted=False
                            )
                            self.cells[c_addr] = cell
                    except Exception:
                        pass
            elif isinstance(byte_addr, z3.BitVecNumRef):
                c_addr = byte_addr.as_long()
                if c_addr in self.cells:
                    cell = self.cells[c_addr]
                elif self.memory_provider:
                    try:
                        raw_byte = self.memory_provider(c_addr, 1)
                        if raw_byte:
                            byte_val = int.from_bytes(raw_byte, byteorder='little')
                            cell = StackByteCell(
                                byte_ast=z3.BitVecVal(byte_val, 8),
                                origin_instr='static_memory',
                                timestamp=0,
                                is_tainted=False
                            )
                            self.cells[c_addr] = cell
                    except Exception:
                        pass

            # 2. Symbolic Path: Chaining symbolic writes history
            if cell is None:
                chain = []
                for w_addr, w_cell, w_sz in reversed(self.symbolic_writes):
                    cond = (byte_addr == w_addr)
                    is_t = False
                    is_f = False

                    if isinstance(byte_addr, z3.BitVecNumRef) and isinstance(w_addr, z3.BitVecNumRef):
                        if byte_addr.as_long() == w_addr.as_long():
                            is_t = True
                        else:
                            is_f = True
                    elif byte_addr.eq(w_addr):
                        is_t = True
                    else:
                        simp_cond = self._safe_simplify(cond)
                        if z3.is_true(simp_cond):
                            is_t = True
                        elif z3.is_false(simp_cond):
                            is_f = True

                    if is_t:
                        chain.append((True, w_cell))
                        break
                    elif is_f:
                        continue
                    else:
                        chain.append((cond, w_cell))

                if not chain or chain[-1][0] is not True:
                    mem_name = f'SymMemRead_{self.mem_read_idx}_t{tick}_b{i}'
                    self.mem_read_idx += 1
                    fallback_ast = z3.BitVec(mem_name, 8)
                    fallback_cell = StackByteCell(
                        byte_ast=fallback_ast,
                        origin_instr='unknown_symbolic',
                        timestamp=tick,
                        is_tainted=True
                    )
                    base_cell = fallback_cell
                else:
                    base_cell = chain.pop()[1]

                curr_ast = base_cell.byte_ast
                curr_origin = base_cell.origin_instr
                curr_ts = base_cell.timestamp
                curr_tainted = base_cell.is_tainted

                while chain:
                    cond, c_item = chain.pop()
                    curr_ast = z3.If(cond, c_item.byte_ast, curr_ast)
                    curr_tainted = curr_tainted or c_item.is_tainted

                cell = StackByteCell(
                    byte_ast=self._safe_simplify(curr_ast),
                    origin_instr=curr_origin,
                    timestamp=curr_ts,
                    is_tainted=curr_tainted
                )

            read_cells.append(cell)

        stitched_ast = self._stitch_bytes_to_ast(read_cells, size_bytes)
        return read_cells, stitched_ast

    def read_val(
        self,
        addr_ast: Union[int, z3.BitVecRef],
        size_bytes: int,
        tick: int = 0
    ) -> z3.BitVecRef:
        """
        Reads `size_bytes` starting at `addr_ast` and returns the stitched BitVec AST.
        """
        _, stitched = self.read_bytes(addr_ast, size_bytes, tick=tick)
        return stitched

    # =========================================================================
    # High-Level Frame & LIFO Stack Operations
    # =========================================================================

    def push(
        self,
        rsp_ast: z3.BitVecRef,
        val_ast: Union[int, z3.BitVecRef],
        size_bytes: int = 8,
        origin_instr: Optional[Any] = None,
        timestamp: int = 0,
        is_tainted: bool = False
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """
        Simulates x86 `push`:
            1. RSP = RSP - size_bytes
            2. [RSP] = val_ast
        Returns `(new_rsp_ast, written_val_ast)`.
        """
        rsp_64 = self._to_64bit_addr(rsp_ast)
        new_rsp = self._safe_simplify(rsp_64 - size_bytes)
        self.write_val(new_rsp, val_ast, size_bytes, origin_instr=origin_instr, timestamp=timestamp, is_tainted=is_tainted)
        return new_rsp, val_ast

    def pop(
        self,
        rsp_ast: z3.BitVecRef,
        size_bytes: int = 8,
        origin_instr: Optional[Any] = None,
        timestamp: int = 0
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """
        Simulates x86 `pop`:
            1. val_ast = [RSP]
            2. RSP = RSP + size_bytes
        Returns `(new_rsp_ast, popped_val_ast)`.
        """
        rsp_64 = self._to_64bit_addr(rsp_ast)
        val_ast = self.read_val(rsp_64, size_bytes, tick=timestamp)
        new_rsp = self._safe_simplify(rsp_64 + size_bytes)
        return new_rsp, val_ast

    def write_slot(
        self,
        base_ast: z3.BitVecRef,
        disp: int,
        val_ast: Union[int, z3.BitVecRef],
        size_bytes: int = 4,
        origin_instr: Optional[Any] = None,
        timestamp: int = 0,
        is_tainted: bool = False
    ) -> None:
        """
        Writes a frame slot relative to base: `[base_ast + disp] = val_ast`.
        """
        base_64 = self._to_64bit_addr(base_ast)
        target_addr = self._safe_simplify(base_64 + disp)
        self.write_val(target_addr, val_ast, size_bytes, origin_instr=origin_instr, timestamp=timestamp, is_tainted=is_tainted)

    def read_slot(
        self,
        base_ast: z3.BitVecRef,
        disp: int,
        size_bytes: int = 4,
        tick: int = 0
    ) -> Tuple[z3.BitVecRef, List[StackByteCell]]:
        """
        Reads a frame slot relative to base: `[base_ast + disp]`.
        Returns `(stitched_ast, list_of_cells)`.
        """
        base_64 = self._to_64bit_addr(base_ast)
        target_addr = self._safe_simplify(base_64 + disp)
        cells, stitched = self.read_bytes(target_addr, size_bytes, tick=tick)
        return stitched, cells

    def get_provenance(
        self,
        addr_ast: Union[int, z3.BitVecRef],
        size_bytes: int,
        tick: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Returns structured provenance metadata for each byte in the requested range.
        """
        cells, _ = self.read_bytes(addr_ast, size_bytes, tick=tick)
        provenance = []
        for idx, c in enumerate(cells):
            provenance.append({
                'byte_offset': idx,
                'ast': c.byte_ast,
                'origin_instr': c.origin_instr,
                'timestamp': c.timestamp,
                'is_tainted': c.is_tainted
            })
        return provenance
