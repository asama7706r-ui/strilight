import struct
from typing import List, Dict, Any, Optional
from strilight.engine.vsa.models import AffineExpr, RegisterCouplingMatrix, LoopSummary
from strilight.engine.vsa.state_ops import get_operand_list
from strilight.engine.x86_defs import REG_TO_BASE


class SymbolicInductionAnalyzer:
    """
    Analyzes a loop body symbolically in a single pass (Zero-Spinning O(1)).
    Extracts affine strides, register coupling matrices, geometric shifts,
    and table pattern scaling.
    """

    @classmethod
    def evaluate_symbolic_pass(
        cls,
        body: List[Any],
        summary: LoopSummary,
        memory_provider: Optional[Any] = None
    ) -> bool:
        """
        Executes a single symbolic pass over the loop body to extract affine deltas,
        register coupling matrix, geometric shifts, and compound table multipliers without spinning.
        """
        env: Dict[str, AffineExpr] = {}
        reg_origins: Dict[str, str] = {}
        shift_exprs: Dict[str, Dict[str, Any]] = {}
        table_exprs: Dict[str, Dict[str, Any]] = {}

        all_regs = set()
        for record in body:
            if hasattr(record, 'body'):
                continue
            all_regs.update(getattr(record, 'regs_read', []))
            all_regs.update(getattr(record, 'regs_write', []))
            for op in get_operand_list(record):
                if op.get('type') == 'reg':
                    all_regs.add(op['value'])

        for r in all_regs:
            env[r] = AffineExpr.from_reg(r)
            reg_origins[r] = r

        for record in body:
            if hasattr(record, 'body'):
                continue
            mnemonic = getattr(record, 'mnemonic', '').lower()
            operands = get_operand_list(record)
            if not operands:
                continue

            dest_op = operands[0] if len(operands) > 0 else None
            src_op = operands[1] if len(operands) > 1 else None

            def get_expr(op):
                if op['type'] == 'imm':
                    return AffineExpr.from_const(op['value'])
                elif op['type'] == 'reg':
                    return env.get(op['value'], AffineExpr.from_reg(op['value']))
                return None

            if dest_op and dest_op['type'] == 'reg':
                dest_reg = dest_op['value']
                if mnemonic == 'mov':
                    if src_op and src_op['type'] == 'reg':
                        src_reg = src_op['value']
                        reg_origins[dest_reg] = reg_origins.get(src_reg, src_reg)
                        if src_reg in table_exprs:
                            table_exprs[dest_reg] = dict(table_exprs[src_reg])
                        if src_reg in shift_exprs:
                            shift_exprs[dest_reg] = dict(shift_exprs[src_reg])
                    elif src_op and src_op['type'] == 'mem':
                        # Dynamically extract table pattern from loaded binary memory
                        extracted_pattern = []
                        if getattr(record, 'mem_read', None) and memory_provider:
                            base_addr = record.mem_read[0]
                            for i in range(8):
                                try:
                                    raw = memory_provider(base_addr + (i * 8), 4)
                                    if raw and len(raw) >= 4:
                                        extracted_pattern.append(struct.unpack('<I', raw[:4])[0])
                                    else:
                                        break
                                except Exception:
                                    break
                        if not extracted_pattern:
                            extracted_pattern = [0]

                        table_exprs[dest_reg] = {
                            'pattern': extracted_pattern,
                            'scale_var': None
                        }
                    src_expr = get_expr(src_op) if src_op else None
                    if src_expr:
                        env[dest_reg] = src_expr
                elif mnemonic == 'imul':
                    if src_op and src_op['type'] == 'reg':
                        scale_var = src_op['value']
                        if dest_reg in table_exprs:
                            table_exprs[dest_reg]['scale_var'] = scale_var
                elif mnemonic == 'add':
                    src_expr = get_expr(src_op) if src_op else None
                    if src_expr:
                        env[dest_reg] = env[dest_reg].add(src_expr)
                    if src_op and src_op['type'] == 'reg':
                        src_reg = src_op['value']
                        # Accumulate compound table terms
                        if src_reg in table_exprs:
                            table_exprs[dest_reg] = dict(table_exprs[src_reg])
                            summary.patterns[dest_reg] = list(table_exprs[src_reg]['pattern'])
                            if table_exprs[src_reg].get('scale_var'):
                                summary.pattern_scales[dest_reg] = table_exprs[src_reg]['scale_var']
                        # Accumulate compound geometric shift terms
                        if src_reg in shift_exprs:
                            shift_exprs[dest_reg] = dict(shift_exprs[src_reg])
                            summary.geometric_shifts[dest_reg] = dict(shift_exprs[src_reg])
                elif mnemonic == 'sub':
                    src_expr = get_expr(src_op) if src_op else None
                    if src_expr:
                        env[dest_reg] = env[dest_reg].sub(src_expr)
                elif mnemonic == 'inc':
                    env[dest_reg] = env[dest_reg].add(AffineExpr.from_const(1))
                elif mnemonic == 'dec':
                    env[dest_reg] = env[dest_reg].sub(AffineExpr.from_const(1))
                elif mnemonic == 'shl':
                    # Rule 6: Check for geometric shift: shl reg, cl where cl is induction counter
                    if src_op and src_op['type'] == 'reg':
                        origin_var = reg_origins.get(dest_reg, dest_reg)
                        shift_info = {
                            'base': 2,
                            'var': origin_var,
                            'val': 1,
                            'modulo_bits': 32
                        }
                        shift_exprs[dest_reg] = shift_info
                        summary.geometric_shifts[dest_reg] = shift_info

        # Identify Loop-Carried registers (registers READ before being WRITTEN in loop body)
        read_first_regs = set()
        written_first_regs = set()
        for record in body:
            if hasattr(record, 'body'):
                continue
            for r in getattr(record, 'regs_read', []):
                base_r = REG_TO_BASE.get(r, r)
                if base_r not in written_first_regs:
                    read_first_regs.add(base_r)
                    read_first_regs.add(r)
            for r in getattr(record, 'regs_write', []):
                base_r = REG_TO_BASE.get(r, r)
                if base_r not in read_first_regs:
                    written_first_regs.add(base_r)
                    written_first_regs.add(r)

        # Analyze extracted expressions for scalar deltas and constant sets
        coupling_regs = list(all_regs)
        matrix = RegisterCouplingMatrix(coupling_regs)

        for r in all_regs:
            final_expr = env.get(r)
            if not final_expr:
                continue
            delta = final_expr.get_scalar_delta(r)
            if delta is not None:
                if delta != 0:
                    summary.deltas[r] = delta
            elif final_expr.is_constant():
                summary.constant_sets[r] = final_expr.offset

            matrix.set_affine_row(r, final_expr)

        # Filter patterns and geometric_shifts to only keep Loop-Carried registers (accumulators)
        summary.patterns = {r: p for r, p in summary.patterns.items() if r in read_first_regs}
        summary.pattern_scales = {r: s for r, s in summary.pattern_scales.items() if r in read_first_regs}
        summary.geometric_shifts = {r: g for r, g in summary.geometric_shifts.items() if r in read_first_regs}

        summary.coupling_matrix = matrix
        return len(summary.deltas) > 0 or len(summary.geometric_shifts) > 0 or len(summary.patterns) > 0
