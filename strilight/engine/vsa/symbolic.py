import struct
import copy
from typing import List, Dict, Any, Optional, Set
from strilight.engine.vsa.models import (
    AffineExpr,
    RegisterCouplingMatrix,
    LoopSummary,
    TelescopingBranch,
    TelescopingCascade,
    LoopTerm,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    TelescopingTerm,
    RegisterLoopExpr,
    ScaleKernel,
    IdentityScale,
    PowerScale,
)
from strilight.engine.vsa.state_ops import get_operand_list
from strilight.engine.x86_defs import REG_TO_BASE, JCC_RELATIONAL_OPS


class SymbolicInductionAnalyzer:
    """
    Analyzes a loop body symbolically in a single pass (Zero-Spinning O(1)).
    Builds the Universal Symbolic Loop Expression AST (RegisterLoopExpr) directly
    for affine strides, register coupling matrices, geometric shifts,
    telescoping cascades, and table pattern scaling.
    """

    @classmethod
    def extract_internal_branches(cls, body: List[Any]) -> List[Dict[str, Any]]:
        """
        Discovers internal condition checks (cmp/test + jcc) inside the loop body
        to formulate telescoping branches.
        """
        branches = []
        pending_cmp = None

        for record in body:
            if hasattr(record, 'body'):
                continue
            mnemonic = getattr(record, 'mnemonic', '').lower()
            operands = get_operand_list(record)

            if mnemonic in ('cmp', 'test'):
                if len(operands) >= 2:
                    lhs = operands[0].get('value')
                    rhs = operands[1].get('value')
                    op_type = 'and_nonzero' if mnemonic == 'test' else 'eq'
                    pending_cmp = {
                        'lhs': lhs,
                        'rhs': rhs,
                        'raw_op': op_type,
                        'record': record
                    }
            elif mnemonic.startswith('j') and mnemonic != 'jmp' and pending_cmp:
                op_name, is_taken = JCC_RELATIONAL_OPS.get(mnemonic, ('eq', True))
                if pending_cmp.get('raw_op') == 'and_nonzero':
                    op_name = 'and_nonzero'

                branches.append({
                    'condition': {
                        'lhs': pending_cmp['lhs'],
                        'op': op_name,
                        'rhs': pending_cmp['rhs'],
                        'is_taken': is_taken
                    },
                    'jump_record': record,
                    'cmp_record': pending_cmp['record']
                })
                pending_cmp = None

        return branches

    @classmethod
    def evaluate_symbolic_pass(
        cls,
        body: List[Any],
        summary: LoopSummary,
        memory_provider: Optional[Any] = None
    ) -> bool:
        """
        Executes a single symbolic pass over the loop body to construct the Universal
        Symbolic Loop Expression AST (register_exprs), coupling matrix, geometric shifts,
        and telescoping cascades.
        """
        env: Dict[str, AffineExpr] = {}
        ast_env: Dict[str, RegisterLoopExpr] = {}
        reg_origins: Dict[str, str] = {}

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
            ast_env[r] = RegisterLoopExpr(r)
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

            def get_affine_expr(op):
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
                        if src_reg in ast_env:
                            ast_env[dest_reg] = copy.deepcopy(ast_env[src_reg])
                            ast_env[dest_reg].name = dest_reg
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

                        ast_env[dest_reg] = RegisterLoopExpr(dest_reg)
                        ast_env[dest_reg].add_term(PeriodicTerm(extracted_pattern))
                    elif src_op and src_op['type'] == 'imm':
                        ast_env[dest_reg] = RegisterLoopExpr(dest_reg).set_constant(src_op['value'])

                    src_expr = get_affine_expr(src_op) if src_op else None
                    if src_expr:
                        env[dest_reg] = src_expr

                elif mnemonic == 'imul':
                    if src_op and src_op['type'] == 'reg':
                        scale_var = src_op['value']
                        if dest_reg in ast_env:
                            for term in ast_env[dest_reg].terms:
                                if isinstance(term, PeriodicTerm):
                                    term.scale_var = scale_var

                elif mnemonic == 'add':
                    src_expr = get_affine_expr(src_op) if src_op else None
                    if src_expr:
                        env[dest_reg] = env[dest_reg].add(src_expr)

                    if src_op and src_op['type'] == 'reg':
                        src_reg = src_op['value']
                        # Absorb and merge terms from source into destination AST
                        if src_reg in ast_env and ast_env[src_reg].terms:
                            for term in ast_env[src_reg].terms:
                                ast_env[dest_reg].add_term(copy.deepcopy(term))

                elif mnemonic == 'sub':
                    src_expr = get_affine_expr(src_op) if src_op else None
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
                        geom_term = GeometricTerm(
                            base=2,
                            var=origin_var,
                            val=1,
                            modulo_bits=32
                        )
                        ast_env[dest_reg] = RegisterLoopExpr(dest_reg).add_term(geom_term)

        # Identify Loop-Carried registers (registers READ before being WRITTEN in loop body)
        read_first_regs: Set[str] = set()
        written_first_regs: Set[str] = set()
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

        # Build Register Coupling Matrix (Rule 7)
        coupling_regs = list(all_regs)
        matrix = RegisterCouplingMatrix(coupling_regs)

        for r in all_regs:
            final_expr = env.get(r)
            if not final_expr:
                continue
            matrix.set_affine_row(r, final_expr)

        summary.coupling_matrix = matrix

        # Populate summary.register_exprs with the unified AST expressions
        for r in all_regs:
            final_expr = env.get(r)
            ast_expr = ast_env.get(r)
            if not final_expr or not ast_expr:
                continue

            delta = final_expr.get_scalar_delta(r)
            is_loop_carried = (r in read_first_regs)

            has_structured_terms = len(ast_expr.terms) > 0

            if is_loop_carried:
                if has_structured_terms:
                    summary.register_exprs[r] = ast_expr
                    for t in ast_expr.terms:
                        if isinstance(t, PeriodicTerm):
                            summary.patterns[r] = t.pattern
                            if t.scale_var:
                                summary.pattern_scales[r] = t.scale_var
                        elif isinstance(t, GeometricTerm):
                            summary.geometric_shifts[r] = {
                                'base': t.base,
                                'var': t.var,
                                'val': t.val,
                                'modulo_bits': t.modulo_bits
                            }
                        elif isinstance(t, TelescopingTerm):
                            summary.telescoping_cascades[r] = t.cascade
                elif delta is not None and delta != 0:
                    summary.register_exprs[r] = RegisterLoopExpr(r).add_term(LinearTerm(delta))
                    summary.deltas[r] = delta
                elif final_expr.is_constant():
                    summary.register_exprs[r] = RegisterLoopExpr(r).set_constant(final_expr.offset)
                    summary.constant_sets[r] = final_expr.offset
            else:
                if final_expr.is_constant():
                    summary.register_exprs[r] = RegisterLoopExpr(r).set_constant(final_expr.offset)
                    summary.constant_sets[r] = final_expr.offset

        return len(summary.register_exprs) > 0 or len(summary.deltas) > 0


