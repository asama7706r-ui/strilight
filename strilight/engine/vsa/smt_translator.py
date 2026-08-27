import z3
import logging
from typing import Dict, List, Any, Optional, Tuple, Callable, Set
from strilight.engine.vsa.models import LoopSummary, TelescopingCascade, RegisterLoopExpr
from strilight.engine.x86_defs import REG_TO_BASE

logger = logging.getLogger("strilight.engine.vsa.smt_translator")


class LoopStateUpdate:
    """
    Represents the computed SMT AST mathematical transformation for a register or memory location.
    The Grand Master Recurrence Equation:
        X(N) = A(N) * X_0 + Delta_total(N)
    where A(N) is the cumulative multiplicative scale kernel (default 1) and Delta_total(N) is
    the combined sum of all active additive components (with inactive components defaulting to neutral 0).
    """
    def __init__(
        self,
        name: str,
        scale_ast: Optional[z3.BitVecRef] = None,
        scale_prev_ast: Optional[z3.BitVecRef] = None,
        delta_ast: Optional[z3.BitVecRef] = None,
        delta_prev_ast: Optional[z3.BitVecRef] = None,
        constant_val: Optional[int] = None,
        is_mem: bool = False,
        mem_addr: Optional[int] = None,
        mem_size_bits: int = 64,
    ):
        self.name = name
        self.scale_ast = scale_ast if scale_ast is not None else z3.BitVecVal(1, 64)
        self.scale_prev_ast = scale_prev_ast if scale_prev_ast is not None else z3.BitVecVal(1, 64)
        self.delta_ast = delta_ast if delta_ast is not None else z3.BitVecVal(0, 64)
        self.delta_prev_ast = delta_prev_ast if delta_prev_ast is not None else z3.BitVecVal(0, 64)
        self.constant_val = constant_val
        self.is_mem = is_mem
        self.mem_addr = mem_addr
        self.mem_size_bits = mem_size_bits


class LoopSMTTranslator:
    """
    SMT-LIB2 / Z3 AST Mathematical Bridge for Loop Summaries.
    Implements the Grand Master Recurrence Equation across all rules in O(1):
        X(N) = A(N) * X_0 + [ Delta_scalar(N) + Delta_poly(N) + Delta_tele(N) + Delta_geom(N) ]
    with neutral identity elements (0 for addition, 1 for multiplication).
    """

    @staticmethod
    def build_polycyclic_delta_ast(
        N_ast: z3.BitVecRef,
        pattern: List[int],
        bit_size: int = 64
    ) -> z3.BitVecRef:
        """
        Builds the closed-form SMT AST for a polycyclic stride pattern:
            Delta(N) = (N // P) * Sum(P) + PrefixSum[N % P]
        """
        P = len(pattern)
        if P == 0:
            return z3.BitVecVal(0, bit_size)
        if all(x == pattern[0] for x in pattern):
            return z3.BitVecVal(pattern[0], bit_size) * N_ast

        P_val = z3.BitVecVal(P, bit_size)
        cycle_sum = sum(pattern)
        cycle_sum_val = z3.BitVecVal(cycle_sum, bit_size)

        Q = z3.UDiv(N_ast, P_val)
        R = z3.URem(N_ast, P_val)

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

    @staticmethod
    def build_geometric_shift_ast(
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        shift_info: Dict[str, Any],
        src_ast: Optional[z3.BitVecRef] = None,
        iterations_bound: Optional[int] = None,
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """
        Builds the closed-form SMT AST for a Geometric Shift Recurrence (Rule 6: Positional Receipt):
            Sum_{i=0}^{N-1} base^i * var = ((base^N - 1) / (base - 1)) * var
        """
        scale_base = shift_info.get('base', 2)
        src_val_imm = shift_info.get('val', 1)
        modulo_bits = shift_info.get('modulo_bits', 0)

        if modulo_bits == 32:
            if isinstance(iterations_bound, int) and iterations_bound > 0:
                shift_coeff = sum(1 << (i & 31) for i in range(iterations_bound)) & 0xFFFFFFFF
                geom_factor = z3.BitVecVal(shift_coeff, 64)
                shift_coeff_prev = sum(1 << (i & 31) for i in range(max(0, iterations_bound - 1))) & 0xFFFFFFFF
                geom_factor_prev = z3.BitVecVal(shift_coeff_prev, 64)
            else:
                full_cycles = z3.UDiv(N_ast, 32)
                rem = z3.URem(N_ast, 32)
                geom_factor = (full_cycles * z3.BitVecVal(0xFFFFFFFF, 64)) + ((z3.BitVecVal(1, 64) << rem) - 1)
                full_cycles_prev = z3.UDiv(N_prev_ast, 32)
                rem_prev = z3.URem(N_prev_ast, 32)
                geom_factor_prev = (full_cycles_prev * z3.BitVecVal(0xFFFFFFFF, 64)) + ((z3.BitVecVal(1, 64) << rem_prev) - 1)
        else:
            if scale_base == 2:
                geom_factor = (z3.BitVecVal(1, 64) << N_ast) - 1
                geom_factor_prev = (z3.BitVecVal(1, 64) << N_prev_ast) - 1
            else:
                geom_factor = z3.UDiv((z3.BitVecVal(scale_base, 64) ** N_ast) - 1, scale_base - 1)
                geom_factor_prev = z3.UDiv((z3.BitVecVal(scale_base, 64) ** N_prev_ast) - 1, scale_base - 1)

        if src_ast is not None:
            if src_ast.size() != 64:
                src_ast = z3.ZeroExt(64 - src_ast.size(), src_ast)
            delta_ast = geom_factor * src_ast
            delta_prev_ast = geom_factor_prev * src_ast
        else:
            delta_ast = geom_factor * z3.BitVecVal(src_val_imm, 64)
            delta_prev_ast = geom_factor_prev * z3.BitVecVal(src_val_imm, 64)

        return delta_ast, delta_prev_ast

    @classmethod
    def build_telescoping_cascade_ast(
        cls,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        reg_name: str,
        cascade: TelescopingCascade,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """
        Builds the closed-form SMT AST for a Telescoping Cascade (Rule 5):
            Delta_total = sum_{k=1}^M (P_k * Delta_k)
            where sum P_k == 1.
        """
        M = len(cascade.branches)
        if M == 0:
            return z3.BitVecVal(0, 64), z3.BitVecVal(0, 64)

        # 1. Build guard indicator expressions P_k for each branch
        guards = []
        accumulated_not_guards = []

        for idx, branch in enumerate(cascade.branches):
            if idx == M - 1 and not branch.conditions:
                # Fallback default branch
                if accumulated_not_guards:
                    p_k = accumulated_not_guards[0]
                    for neg_c in accumulated_not_guards[1:]:
                        p_k = p_k * neg_c
                else:
                    p_k = z3.BitVecVal(1, 64)
                guards.append(p_k)
                continue

            # Build condition AST for branch
            cond_exprs = []
            for cond in branch.conditions:
                lhs_val = resolve_val_fn(cond.get('lhs'))
                rhs_val = resolve_val_fn(cond.get('rhs'))

                if lhs_val is None or rhs_val is None:
                    continue

                if lhs_val.size() != rhs_val.size():
                    max_sz = max(lhs_val.size(), rhs_val.size())
                    lhs_val = z3.ZeroExt(max_sz - lhs_val.size(), lhs_val)
                    rhs_val = z3.ZeroExt(max_sz - rhs_val.size(), rhs_val)

                op = cond.get('op', 'eq')
                if op == 'eq':
                    bool_c = (lhs_val == rhs_val)
                elif op == 'ne':
                    bool_c = (lhs_val != rhs_val)
                elif op in ('gt', 'ja', 'jg'):
                    bool_c = z3.UGT(lhs_val, rhs_val)
                elif op in ('ge', 'jae', 'jge'):
                    bool_c = z3.UGE(lhs_val, rhs_val)
                elif op in ('lt', 'jb', 'jl'):
                    bool_c = z3.ULT(lhs_val, rhs_val)
                elif op in ('le', 'jbe', 'jle'):
                    bool_c = z3.ULE(lhs_val, rhs_val)
                elif op == 'and_nonzero':
                    bool_c = ((lhs_val & rhs_val) != 0)
                else:
                    bool_c = (lhs_val == rhs_val)

                cond_exprs.append(bool_c)

            if cond_exprs:
                branch_bool = cond_exprs[0]
                for c in cond_exprs[1:]:
                    branch_bool = z3.And(branch_bool, c)
                c_k = z3.If(branch_bool, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
            else:
                c_k = z3.BitVecVal(1, 64)

            # P_k = (prod_{j=1}^{k-1} (1 - c_j)) * c_k
            if accumulated_not_guards:
                p_k = accumulated_not_guards[0]
                for neg_c in accumulated_not_guards[1:]:
                    p_k = p_k * neg_c
                p_k = p_k * c_k
            else:
                p_k = c_k

            guards.append(p_k)
            accumulated_not_guards.append(z3.BitVecVal(1, 64) - c_k)

        # 2. Build the unified single-line sum Delta_total = sum(P_k * Delta_k)
        branch_deltas = []
        for branch in cascade.branches:
            d = branch.deltas.get(reg_name, 0)
            branch_deltas.append(z3.BitVecVal(d, 64))

        terms = [g * d for g, d in zip(guards, branch_deltas)]
        if terms:
            combined_delta = terms[0]
            for term in terms[1:]:
                combined_delta = combined_delta + term
        else:
            combined_delta = z3.BitVecVal(0, 64)

        total_tele_delta = combined_delta * N_ast
        total_tele_delta_prev = combined_delta * N_prev_ast
        return total_tele_delta, total_tele_delta_prev

    @classmethod
    def translate_loop_summary_to_smt_updates(
        cls,
        summary: LoopSummary,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        get_phys_reg_fn: Callable[[str], z3.BitVecRef],
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        composed_inner_deltas: Optional[Dict[str, Any]] = None,
        reg_to_base_fn: Optional[Callable[[str], str]] = None,
    ) -> List[LoopStateUpdate]:
        """
        Translates all components of a LoopSummary into canonical SMT AST state updates
        following the Grand Master Recurrence Equation:
            X(N) = A(N) * X_0 + Delta_total(N)
        Evaluates directly through Universal Loop Expression Trees (register_exprs) in O(1).
        """
        to_base = reg_to_base_fn or (lambda r: REG_TO_BASE.get(r, r))
        composed_inner = composed_inner_deltas or {}

        def parse_mem_key(key: str) -> Tuple[bool, Optional[int], int]:
            if key.startswith("MEM_"):
                parts = key.split("_")
                return True, int(parts[1]), int(parts[2])
            return False, None, 64

        # 1. Collect all canonical targets from the Universal AST and composed inner loops
        target_keys: Set[str] = set(summary.register_exprs.keys()) | set(composed_inner.keys())

        canonical_targets: Dict[str, Set[str]] = {}
        for raw_k in target_keys:
            is_mem, _, _ = parse_mem_key(raw_k)
            dest = raw_k if is_mem else to_base(raw_k)
            if dest not in canonical_targets:
                canonical_targets[dest] = set()
            canonical_targets[dest].add(raw_k)

        updates: List[LoopStateUpdate] = []

        # 2. Evaluate Grand Master Recurrence for each target
        for dest_key, raw_aliases in canonical_targets.items():
            is_mem, mem_addr, mem_sz = parse_mem_key(dest_key)

            # Check if this target is driven by a child inner loop
            has_composed_inner = False
            inner_step_delta = None
            for alias in raw_aliases:
                if alias in composed_inner:
                    has_composed_inner = True
                    inner_step_delta = composed_inner[alias]
                    break

            if has_composed_inner and inner_step_delta is not None:
                direct_d = 0
                for alias in raw_aliases:
                    if alias in getattr(summary, 'direct_deltas', {}):
                        direct_d = summary.direct_deltas[alias]
                        break

                total_delta_n = (inner_step_delta + direct_d) * N_ast
                total_delta_prev = (inner_step_delta + direct_d) * N_prev_ast

                updates.append(LoopStateUpdate(
                    name=dest_key,
                    scale_ast=z3.BitVecVal(1, 64),
                    scale_prev_ast=z3.BitVecVal(1, 64),
                    delta_ast=z3.simplify(total_delta_n),
                    delta_prev_ast=z3.simplify(total_delta_prev),
                    is_mem=is_mem,
                    mem_addr=mem_addr,
                    mem_size_bits=mem_sz,
                ))
                continue

            # Retrieve the matched Universal AST Expression
            matched_expr: Optional[RegisterLoopExpr] = None
            for alias in raw_aliases:
                if alias in summary.register_exprs:
                    matched_expr = summary.register_exprs[alias]
                    break

            if matched_expr is not None:
                # Constant Definition
                if matched_expr.constant_val is not None:
                    updates.append(LoopStateUpdate(
                        name=dest_key,
                        constant_val=matched_expr.constant_val,
                        is_mem=is_mem,
                        mem_addr=mem_addr,
                        mem_size_bits=mem_sz,
                    ))
                    continue

                # Recurrence Equation Evaluation via AST
                scale_n, scale_prev, total_delta_n, total_delta_prev = matched_expr.to_smt(
                    N_ast=N_ast,
                    N_prev_ast=N_prev_ast,
                    resolve_val_fn=resolve_val_fn,
                    bit_size=64
                )

                updates.append(LoopStateUpdate(
                    name=dest_key,
                    scale_ast=z3.simplify(scale_n),
                    scale_prev_ast=z3.simplify(scale_prev),
                    delta_ast=z3.simplify(total_delta_n),
                    delta_prev_ast=z3.simplify(total_delta_prev),
                    is_mem=is_mem,
                    mem_addr=mem_addr,
                    mem_size_bits=mem_sz,
                ))

        return updates

    @classmethod
    def build_loop_exit_constraints(
        cls,
        summary: LoopSummary,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        get_phys_reg_fn: Optional[Callable[[str], z3.BitVecRef]] = None,
    ) -> List[Tuple[z3.BoolRef, str]]:
        """
        Builds the closed-form SMT AST constraints for Loop Termination and Continuation Guards.
            Exit Constraint (At Step N):        Guard(X(N)) == Exit Condition
            Continuation Guard (At Step N-1):   Guard(X(N-1)) == Continue Condition (Implies N > 0)
        Evaluates directly in O(1) through Universal Expression Tree ASTs without instruction replay.
        """
        lhs = None
        rhs = None
        jcc = "je"
        is_exit_on_true = True

        if getattr(summary, 'exit_guard', None) is not None:
            guard = summary.exit_guard
            lhs = guard.lhs
            rhs = guard.rhs
            jcc = guard.jcc
            is_exit_on_true = guard.is_exit_on_true
        elif getattr(summary, 'exit_records', None):
            # Fallback heuristic extraction from raw exit records
            last_jcc = None
            cmp_record = None
            for r in reversed(summary.exit_records):
                if last_jcc is None and hasattr(r, 'mnemonic') and r.mnemonic.startswith('j') and r.mnemonic != 'jmp':
                    last_jcc = r
                elif last_jcc is not None and hasattr(r, 'mnemonic') and r.mnemonic in ('cmp', 'test', 'sub'):
                    cmp_record = r
                    break

            if last_jcc is not None and cmp_record is not None and getattr(cmp_record, 'operands', None):
                ops = cmp_record.operands
                if len(ops) >= 2:
                    lhs = ops[0].get('value') if ops[0].get('type') == 'reg' else ops[0]
                    rhs = ops[1].get('value') if ops[1].get('type') in ('reg', 'imm') else ops[1]
                elif len(ops) == 1:
                    lhs = ops[0].get('value') if ops[0].get('type') == 'reg' else ops[0]
                    rhs = 0
                jcc = last_jcc.mnemonic
                is_exit_on_true = getattr(last_jcc, 'jump_taken', True)
                if is_exit_on_true is None:
                    is_exit_on_true = True

        if lhs is None or rhs is None:
            return []

        def eval_target_at_step(target: Any) -> Tuple[Optional[z3.BitVecRef], Optional[z3.BitVecRef]]:
            matched_expr = None
            base_val = None

            if isinstance(target, str):
                base_var = target.lower().strip()
                if base_var in summary.register_exprs:
                    matched_expr = summary.register_exprs[base_var]
                else:
                    for k, expr in summary.register_exprs.items():
                        if REG_TO_BASE.get(k, k) == REG_TO_BASE.get(base_var, base_var):
                            matched_expr = expr
                            break

                base_val = resolve_val_fn(base_var)
                if base_val is None:
                    base_val = z3.BitVecVal(0, 64)

            elif isinstance(target, dict) and target.get('type') == 'mem':
                base_val = resolve_val_fn(target)
                if base_val is None:
                    base_val = z3.BitVecVal(0, 64)

                mem_size = target.get('size', 8) * 8
                disp = target.get('disp', 0)
                base_reg = target.get('base')
                base_reg_val = resolve_val_fn(base_reg) if base_reg else None
                if isinstance(base_reg_val, z3.BitVecNumRef):
                    concrete_addr = base_reg_val.as_long() + disp
                    mem_key = f"MEM_{concrete_addr}_{mem_size}"
                    if mem_key in summary.register_exprs:
                        matched_expr = summary.register_exprs[mem_key]

                # Match from exit records if base register is symbolic (e.g. rbp / rsp)
                if matched_expr is None and getattr(summary, 'exit_records', None):
                    for r in summary.exit_records:
                        for op in getattr(r, 'operands', []):
                            if isinstance(op, dict) and op.get('type') == 'mem':
                                if op.get('base') == base_reg and op.get('disp', 0) == disp:
                                    addr_list = getattr(r, 'mem_read', None) or getattr(r, 'mem_write', None)
                                    if addr_list:
                                        mem_key = f"MEM_{addr_list[0]}_{mem_size}"
                                        if mem_key in summary.register_exprs:
                                            matched_expr = summary.register_exprs[mem_key]
                                            break
                        if matched_expr is not None:
                            break
            else:
                val = resolve_val_fn(target)
                return val, val

            if matched_expr is not None and matched_expr.constant_val is None:
                scale_n, scale_prev, delta_n, delta_prev = matched_expr.to_smt(
                    N_ast=N_ast,
                    N_prev_ast=N_prev_ast,
                    resolve_val_fn=resolve_val_fn,
                    bit_size=base_val.size() if hasattr(base_val, 'size') else 64
                )
                val_at_N = (scale_n * base_val) + delta_n
                val_at_prev = z3.If(N_ast > 0, (scale_prev * base_val) + delta_prev, base_val)
                return val_at_N, val_at_prev
            else:
                return base_val, base_val

        lhs_N, lhs_prev = eval_target_at_step(lhs)
        rhs_N, rhs_prev = eval_target_at_step(rhs)

        if lhs_N is None or rhs_N is None:
            return []

        # Normalize bit sizes
        max_sz = max(lhs_N.size(), rhs_N.size())
        if lhs_N.size() < max_sz:
            lhs_N = z3.ZeroExt(max_sz - lhs_N.size(), lhs_N)
        if rhs_N.size() < max_sz:
            rhs_N = z3.ZeroExt(max_sz - rhs_N.size(), rhs_N)

        if lhs_prev is not None and lhs_prev.size() < max_sz:
            lhs_prev = z3.ZeroExt(max_sz - lhs_prev.size(), lhs_prev)
        if rhs_prev is not None and rhs_prev.size() < max_sz:
            rhs_prev = z3.ZeroExt(max_sz - rhs_prev.size(), rhs_prev)

        def _build_cond_pred(l: z3.BitVecRef, r: z3.BitVecRef, op_mnemonic: str) -> z3.BoolRef:
            op_m = op_mnemonic.lower().strip()
            if op_m in ('je', 'jz', 'eq'):
                return l == r
            elif op_m in ('jne', 'jnz', 'ne'):
                return l != r
            elif op_m in ('ja', 'jnbe', 'ugt'):
                return z3.UGT(l, r)
            elif op_m in ('jae', 'jnb', 'jnc', 'uge'):
                return z3.UGE(l, r)
            elif op_m in ('jb', 'jc', 'jnae', 'ult'):
                return z3.ULT(l, r)
            elif op_m in ('jbe', 'jna', 'ule'):
                return z3.ULE(l, r)
            elif op_m in ('jg', 'jnle', 'gt'):
                return l > r
            elif op_m in ('jge', 'jnl', 'ge'):
                return l >= r
            elif op_m in ('jl', 'jnge', 'lt'):
                return l < r
            elif op_m in ('jle', 'jng', 'le'):
                return l <= r
            return l == r

        cond_N = _build_cond_pred(lhs_N, rhs_N, jcc)
        cond_prev = _build_cond_pred(lhs_prev, rhs_prev, jcc)

        if is_exit_on_true:
            exit_constraint = cond_N
            continue_guard = z3.Not(cond_prev)
        else:
            exit_constraint = z3.Not(cond_N)
            continue_guard = cond_prev

        return [
            (z3.simplify(exit_constraint), "Loop Exit Exact Bound (Step N)"),
            (z3.simplify(z3.Implies(N_ast > 0, continue_guard)), "Loop Exit Continuation Guard (Step N-1)"),
        ]
