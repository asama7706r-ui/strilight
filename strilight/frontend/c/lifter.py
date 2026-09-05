"""
Strilight C Loop Lifter (strilight.frontend.c.lifter)
=====================================================
Extracts mathematical loop summaries directly from C AST nodes and source code using pycparser.
"""

import re
import logging
from fractions import Fraction
from typing import Dict, List, Any, Optional, Tuple, Union, Set
import pycparser
from pycparser import c_parser, c_ast

from strilight.engine.vsa.models import (
    VariableLoopExpr,
    LoopSummary,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    ScaleKernel,
    PowerScale,
    AffineExpr,
    VariableCouplingMatrix,
    ArraySliceMutation,
)
from strilight.frontend.base import BaseLanguageLifter

logger = logging.getLogger(__name__)


class CLoopLifter(BaseLanguageLifter):
    """
    Parses C code using pycparser and extracts loop induction formulas, nested compositions,
    and multi-variable coupled recurrence matrices.
    """

    def __init__(self):
        self.parser = c_parser.CParser()

    def lift(
        self,
        c_code: str,
        contract: Optional[Any] = None,
        scope_env: Optional[Dict[str, Any]] = None
    ) -> LoopSummary:
        wrapped_code = self._wrap_code_if_needed(c_code)
        ast_root = self.parser.parse(wrapped_code)
        
        summary = LoopSummary()
        if contract is not None:
            summary.contract = contract
            if contract.target:
                summary.target_collection = contract.target

        visitor = CForLoopVisitor(summary, scope_env=scope_env, contract=contract)
        visitor.visit(ast_root)
        return summary

    def _wrap_code_if_needed(self, c_code: str) -> str:
        clean = c_code.strip()
        is_fn = bool(re.match(r'^(void|int|double|float|char|bool|uint32_t|int64_t|size_t)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(', clean))
        if not is_fn:
            return f"void __strilight_extracted_loop() {{\n{clean}\n}}"
        return clean


class CForLoopVisitor(c_ast.NodeVisitor):
    """
    Visits C AST For nodes to extract loop invariants, iterations, and statements.
    """

    def __init__(
        self,
        summary: LoopSummary,
        scope_env: Optional[Dict[str, Any]] = None,
        contract: Optional[Any] = None
    ):
        self.summary = summary
        self.scope_env = scope_env or {}
        self.contract = contract
        self.outer_loop_visited = False

    def visit_For(self, node: c_ast.For):
        if not self.outer_loop_visited:
            self.outer_loop_visited = True
            loop_var, n_iters, symbolic_n = self._extract_for_bounds(node)
            self.summary.iterations = n_iters
            self.summary.symbolic_iterations = symbolic_n
            self._analyze_body(node.stmt, loop_var=loop_var)
        else:
            self.generic_visit(node)

    def visit_While(self, node: c_ast.While):
        if not self.outer_loop_visited:
            self.outer_loop_visited = True
            loop_var, n_iters, symbolic_n = self._extract_while_bounds(node)
            self.summary.iterations = n_iters
            self.summary.symbolic_iterations = symbolic_n
            self._analyze_body(node.stmt, loop_var=loop_var)
        else:
            self.generic_visit(node)

    def _extract_for_bounds(self, node: c_ast.For) -> Tuple[str, Optional[int], Optional[str]]:
        loop_var = "i"
        start_val = 0

        # 1. Extract loop variable and initial value from init
        if isinstance(node.init, c_ast.DeclList) and node.init.decls:
            decl = node.init.decls[0]
            loop_var = decl.name
            if decl.init:
                v, _ = self._eval_c_expr(decl.init, "")
                if v is not None:
                    start_val = v
        elif isinstance(node.init, c_ast.Assignment):
            v_name = self._get_var_name(node.init.lvalue)
            if v_name:
                loop_var = v_name
            v, _ = self._eval_c_expr(node.init.rvalue, "")
            if v is not None:
                start_val = v

        # 2. Extract step from next
        step_val = 1
        if node.next:
            if isinstance(node.next, c_ast.UnaryOp):
                if node.next.op in ('p++', '++'):
                    step_val = 1
                elif node.next.op in ('p--', '--'):
                    step_val = -1
            elif isinstance(node.next, c_ast.Assignment):
                if node.next.op == '+=':
                    v, _ = self._eval_c_expr(node.next.rvalue, "")
                    if v is not None:
                        step_val = v
                elif node.next.op == '-=':
                    v, _ = self._eval_c_expr(node.next.rvalue, "")
                    if v is not None:
                        step_val = -v
                elif node.next.op == '=':
                    aff = self._extract_affine_c_node(node.next.rvalue)
                    if aff is not None and aff.coeffs.get(loop_var, 0) == 1:
                        step_val = aff.offset

        # 3. Extract condition bound and operator
        n_iters = None
        symbolic_n = None

        if isinstance(node.cond, c_ast.BinaryOp):
            op = node.cond.op
            left_name = self._get_var_name(node.cond.left)
            right_name = self._get_var_name(node.cond.right)

            if left_name == loop_var:
                bound_node = node.cond.right
            elif right_name == loop_var:
                bound_node = node.cond.left
                op = '<' if op == '>' else ('>' if op == '<' else ('<=' if op == '>=' else '>='))
            else:
                bound_node = node.cond.right

            bound_val, bound_sym = self._eval_c_expr(bound_node, loop_var)
            if bound_sym and self.scope_env and bound_sym in self.scope_env:
                scope_v = self.scope_env[bound_sym]
                if isinstance(scope_v, int):
                    bound_val = scope_v
                    bound_sym = None
                elif isinstance(scope_v, Fraction) and scope_v.denominator == 1:
                    bound_val = scope_v.numerator
                    bound_sym = None

            if bound_val is not None and isinstance(start_val, int) and isinstance(step_val, int) and step_val != 0:
                if op in ('<', '<='):
                    limit = bound_val if op == '<' else bound_val + 1
                    diff = limit - start_val
                    if diff > 0 and step_val > 0:
                        n_iters = (diff + step_val - 1) // step_val
                    else:
                        n_iters = 0
                elif op in ('>', '>='):
                    limit = bound_val if op == '>' else bound_val - 1
                    diff = start_val - limit
                    abs_step = abs(step_val)
                    if diff > 0 and abs_step > 0:
                        n_iters = (diff + abs_step - 1) // abs_step
                    else:
                        n_iters = 0
            else:
                symbolic_n = bound_sym or (str(bound_val) if bound_val is not None else None)

        return loop_var, n_iters, symbolic_n

    def _extract_while_bounds(self, node: c_ast.While) -> Tuple[str, Optional[int], Optional[str]]:
        loop_var = "i"
        start_val = 0
        n_iters = None
        symbolic_n = None

        if isinstance(node.cond, c_ast.BinaryOp):
            op = node.cond.op
            v_name = self._get_var_name(node.cond.left)
            if v_name:
                loop_var = v_name
                bound_node = node.cond.right
            else:
                loop_var = self._get_var_name(node.cond.right) or "i"
                bound_node = node.cond.left
                op = '<' if op == '>' else ('>' if op == '<' else ('<=' if op == '>=' else '>='))

            bound_val, bound_sym = self._eval_c_expr(bound_node, loop_var)
            if bound_sym and self.scope_env and bound_sym in self.scope_env:
                scope_v = self.scope_env[bound_sym]
                if isinstance(scope_v, int):
                    bound_val = scope_v
                    bound_sym = None
                elif isinstance(scope_v, Fraction) and scope_v.denominator == 1:
                    bound_val = scope_v.numerator
                    bound_sym = None

            # Detect step from inside the while body
            step_val = 1
            stmts = node.stmt.block_items if isinstance(node.stmt, c_ast.Compound) else [node.stmt]
            for s in (stmts or []):
                if isinstance(s, c_ast.UnaryOp) and self._get_var_name(s.expr) == loop_var:
                    if s.op in ('p++', '++'):
                        step_val = 1
                    elif s.op in ('p--', '--'):
                        step_val = -1
                elif isinstance(s, c_ast.Assignment) and self._get_var_name(s.lvalue) == loop_var:
                    if s.op == '+=':
                        v, _ = self._eval_c_expr(s.rvalue, "")
                        if v is not None:
                            step_val = v
                    elif s.op == '-=':
                        v, _ = self._eval_c_expr(s.rvalue, "")
                        if v is not None:
                            step_val = -v

            if op in ('>', '>='):
                if bound_val == 0 and step_val < 0:
                    symbolic_n = loop_var
                    return loop_var, None, symbolic_n
                else:
                    limit = bound_val if op == '>' else bound_val - 1
                    diff = start_val - limit
                    abs_step = abs(step_val)
                    if diff > 0 and abs_step > 0:
                        n_iters = (diff + abs_step - 1) // abs_step
                    else:
                        n_iters = 0
            elif op in ('<', '<='):
                if bound_val is not None and isinstance(start_val, int) and isinstance(step_val, int) and step_val > 0:
                    limit = bound_val if op == '<' else bound_val + 1
                    diff = limit - start_val
                    if diff > 0:
                        n_iters = (diff + step_val - 1) // step_val
                    else:
                        n_iters = 0
                else:
                    symbolic_n = bound_sym or (str(bound_val) if bound_val is not None else None)

        return loop_var, n_iters, symbolic_n

    def _normalize_lvalue(self, node: Optional[c_ast.Node], loop_var: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """
        Normalizes any C lvalue AST node into:
        (category, target_identifier, sub_field)
        where category is:
          - 'scalar': target_identifier is 'x', 'total', 'obj.pos'
          - 'array_seq': target_identifier is 'arr', sub_field is None (arr[i])
          - 'struct_array_seq': target_identifier is 'bodies', sub_field is 'x' (bodies[i].x)
        """
        if node is None:
            return None

        if isinstance(node, c_ast.ID):
            return 'scalar', node.name, None

        elif isinstance(node, c_ast.StructRef):
            # Could be bodies[i].x or obj.x or p->x
            if isinstance(node.name, c_ast.ArrayRef):
                arr_name = self._get_var_name(node.name.name)
                subscript_name = self._get_var_name(node.name.subscript)
                field_name = node.field.name if isinstance(node.field, c_ast.ID) else str(node.field)
                if arr_name:
                    if subscript_name == loop_var:
                        return 'struct_array_seq', arr_name, field_name
                    else:
                        return 'array_unstructured', arr_name, field_name
            else:
                var_name = self._get_var_name(node)
                if var_name:
                    return 'scalar', var_name, None

        elif isinstance(node, c_ast.ArrayRef):
            arr_name = self._get_var_name(node.name)
            subscript_name = self._get_var_name(node.subscript)
            if arr_name:
                if subscript_name == loop_var:
                    return 'array_seq', arr_name, None
                else:
                    return 'array_unstructured', arr_name, None

        return None

    def _analyze_body(self, stmt_node: c_ast.Node, loop_var: str):
        stmts = stmt_node.block_items if isinstance(stmt_node, c_ast.Compound) else [stmt_node]
        if not stmts:
            return

        # Check for multi-variable coupled recurrence first (Rule 7)
        coupled_mat = self._detect_coupled_system(stmts)
        if coupled_mat:
            self.summary.coupling_matrix = coupled_mat
            for v in coupled_mat.vars:
                if v not in self.summary.var_exprs:
                    self.summary.var_exprs[v] = VariableLoopExpr(v)
            return

        for stmt in stmts:
            # Skip loop variable self-increments in while loops
            if isinstance(stmt, c_ast.UnaryOp) and self._get_var_name(stmt.expr) == loop_var:
                continue
            if isinstance(stmt, c_ast.Assignment) and self._get_var_name(stmt.lvalue) == loop_var:
                continue

            lval_node = stmt.expr if isinstance(stmt, c_ast.UnaryOp) else getattr(stmt, 'lvalue', None)
            lval_info = self._normalize_lvalue(lval_node, loop_var) if lval_node else None

            if isinstance(stmt, c_ast.UnaryOp):
                stride = 1 if stmt.op in ('p++', '++') else (-1 if stmt.op in ('p--', '--') else 0)
                if lval_info:
                    cat, name, field = lval_info
                    if cat == 'scalar':
                        self._add_delta(name, stride=stride)
                    elif cat == 'array_seq':
                        self._add_array_mutation(name, stride)
                    elif cat == 'struct_array_seq':
                        self._add_array_mutation(f"{name}.{field}", stride)
                else:
                    var_name = self._get_var_name(stmt.expr)
                    if var_name:
                        self._add_delta(var_name, stride=stride)

            elif isinstance(stmt, c_ast.Assignment):
                if lval_info and lval_info[0] in ('array_seq', 'struct_array_seq'):
                    cat, name, field = lval_info
                    target_key = name if cat == 'array_seq' else f"{name}.{field}"
                    self._handle_c_array_mutation(stmt, loop_var, target_key=target_key)
                elif lval_info and lval_info[0] == 'array_unstructured':
                    cat, name, field = lval_info
                    logger.warning(
                        "[accelerate_c] Unstructured or non-sequential array write target for array '%s'. Gracefully falling back.",
                        name
                    )
                    self.summary.has_unsupported_ops = True
                else:
                    var_name = self._get_var_name(stmt.lvalue)
                    if var_name:
                        if stmt.op == '+=':
                            stride, dynamic_expr = self._eval_c_expr(stmt.rvalue, loop_var)
                            self._add_delta(var_name, stride, dynamic_expr)
                        elif stmt.op == '-=':
                            stride, dynamic_expr = self._eval_c_expr(stmt.rvalue, loop_var)
                            self._add_delta(var_name, -stride if stride else None, dynamic_expr)
                        elif stmt.op == '*=':
                            base_val, _ = self._eval_c_expr(stmt.rvalue, loop_var)
                            if base_val is not None and base_val > 0:
                                self._set_scale_kernel(var_name, PowerScale(base=base_val))
                            else:
                                self.summary.has_unsupported_ops = True
                        elif stmt.op == '<<=':
                            shift_val, _ = self._eval_c_expr(stmt.rvalue, loop_var)
                            if shift_val is not None and shift_val >= 0:
                                self._set_scale_kernel(var_name, PowerScale(base=1 << shift_val))
                            else:
                                self.summary.has_unsupported_ops = True
                        elif stmt.op == '=':
                            aff = self._extract_affine_c_node(stmt.rvalue)
                            if aff is not None:
                                coeff = aff.coeffs.get(var_name, 0)
                                other_coeffs = {k: v for k, v in aff.coeffs.items() if k != var_name}
                                if not other_coeffs:
                                    if coeff == 1:
                                        self._add_delta(var_name, stride=aff.offset)
                                    elif coeff > 1 and aff.offset == 0:
                                        self._set_scale_kernel(var_name, PowerScale(base=coeff))
                                    elif coeff == 0:
                                        if var_name not in self.summary.var_exprs:
                                            self.summary.var_exprs[var_name] = VariableLoopExpr(var_name)
                                        self.summary.var_exprs[var_name].constant_val = aff.offset
                                    else:
                                        self.summary.has_unsupported_ops = True
                                else:
                                    self.summary.has_unsupported_ops = True
                            else:
                                self.summary.has_unsupported_ops = True

            elif isinstance(stmt, c_ast.If):
                self._handle_c_if_branch(stmt, loop_var)

            elif isinstance(stmt, c_ast.For):
                # Nested C Loop
                inner_var, inner_n, _ = self._extract_for_bounds(stmt)
                inner_n_val = inner_n or 1
                inner_stmts = stmt.stmt.block_items if isinstance(stmt.stmt, c_ast.Compound) else [stmt.stmt]
                
                for inner_s in (inner_stmts or []):
                    if isinstance(inner_s, c_ast.Assignment) and inner_s.op == '+=':
                        v_name = self._get_var_name(inner_s.lvalue)
                        if v_name:
                            stride, dyn_expr = self._eval_c_expr(inner_s.rvalue, inner_var)
                            index_sum = (inner_n_val * (inner_n_val - 1)) // 2
                            total_inner_step = (stride * inner_n_val) if stride is not None else None
                            
                            if total_inner_step is not None:
                                self._add_delta(v_name, total_inner_step + index_sum, dyn_expr)
                            elif dyn_expr:
                                composed_dyn = f"({inner_n_val} * ({dyn_expr}) + {index_sum})"
                                self._add_delta(v_name, None, composed_dyn)

    def _detect_coupled_system(self, stmts: List[c_ast.Node]) -> Optional[VariableCouplingMatrix]:
        temp_map: Dict[str, AffineExpr] = {}
        curr_state: Dict[str, AffineExpr] = {}
        modified_vars: set = set()

        def _substitute_affine(aff: AffineExpr, state_map: Dict[str, AffineExpr]) -> AffineExpr:
            res = AffineExpr(offset=aff.offset)
            for reg, coeff in aff.coeffs.items():
                if reg in state_map:
                    res = res.add(state_map[reg].mul_const(coeff))
                else:
                    res = res.add(AffineExpr({reg: coeff}, 0))
            return res

        for s in stmts:
            if isinstance(s, c_ast.Decl) and s.init:
                aff = self._extract_affine_c_node(s.init)
                if aff:
                    temp_map[s.name] = _substitute_affine(aff, curr_state)
            elif isinstance(s, c_ast.UnaryOp):
                var_name = self._get_var_name(s.expr)
                if var_name:
                    if var_name not in curr_state:
                        curr_state[var_name] = AffineExpr.from_reg(var_name)
                    if s.op in ('p++', '++'):
                        curr_state[var_name] = curr_state[var_name].add(AffineExpr.from_const(1))
                        modified_vars.add(var_name)
                    elif s.op in ('p--', '--'):
                        curr_state[var_name] = curr_state[var_name].sub(AffineExpr.from_const(1))
                        modified_vars.add(var_name)
            elif isinstance(s, c_ast.Assignment):
                var_name = self._get_var_name(s.lvalue)
                if not var_name:
                    continue
                if var_name not in curr_state:
                    curr_state[var_name] = AffineExpr.from_reg(var_name)

                if s.op == '=':
                    rhs_aff = None
                    if isinstance(s.rvalue, c_ast.ID) and s.rvalue.name in temp_map:
                        rhs_aff = temp_map[s.rvalue.name]
                    else:
                        base_rhs = self._extract_affine_c_node(s.rvalue)
                        if base_rhs:
                            rhs_aff = _substitute_affine(base_rhs, curr_state)
                    if rhs_aff:
                        curr_state[var_name] = rhs_aff
                        modified_vars.add(var_name)
                elif s.op in ('+=', '-='):
                    base_rhs = self._extract_affine_c_node(s.rvalue)
                    if base_rhs:
                        sub_rhs = _substitute_affine(base_rhs, curr_state)
                        if s.op == '+=':
                            curr_state[var_name] = curr_state[var_name].add(sub_rhs)
                        else:
                            curr_state[var_name] = curr_state[var_name].sub(sub_rhs)
                        modified_vars.add(var_name)

        if len(modified_vars) >= 2:
            vars_list = sorted(modified_vars)
            mat = VariableCouplingMatrix(vars_list)
            for v in vars_list:
                mat.set_affine_row(v, curr_state[v])

            # A matrix represents a truly coupled recurrence only if there is
            # cross-variable dependency (off-diagonal != 0) or non-identity scaling (diagonal != 1).
            # If every row is just v_i = v_i + offset, they are independent linear strides!
            has_coupling = False
            for i in range(mat.dim):
                for j in range(mat.dim):
                    expected = 1 if i == j else 0
                    if mat.matrix[i][j] != expected:
                        has_coupling = True
                        break
                if has_coupling:
                    break

            if has_coupling:
                return mat
        return None

    def _extract_affine_c_node(self, node: c_ast.Node) -> Optional[AffineExpr]:
        if isinstance(node, c_ast.Constant):
            try:
                return AffineExpr.from_const(int(node.value, 0))
            except ValueError:
                try:
                    val_str = str(node.value).rstrip("fFlL")
                    return AffineExpr.from_const(Fraction(val_str))
                except Exception:
                    return None
        elif isinstance(node, c_ast.ID):
            if self.scope_env and node.name in self.scope_env:
                val = self.scope_env[node.name]
                if isinstance(val, (int, float, Fraction)):
                    return AffineExpr.from_const(val)
            return AffineExpr.from_reg(node.name)
        elif isinstance(node, c_ast.StructRef):
            var_name = self._get_var_name(node)
            if var_name:
                return AffineExpr.from_reg(var_name)
        elif isinstance(node, c_ast.UnaryOp) and node.op == '-':
            sub = self._extract_affine_c_node(node.expr)
            return sub.mul_const(-1) if sub else None
        elif isinstance(node, c_ast.BinaryOp):
            left = self._extract_affine_c_node(node.left)
            right = self._extract_affine_c_node(node.right)
            if left is None or right is None:
                return None
            if node.op == '+':
                return left.add(right)
            elif node.op == '-':
                return left.sub(right)
            elif node.op == '*':
                if left.is_constant():
                    return right.mul_const(left.offset)
                elif right.is_constant():
                    return left.mul_const(right.offset)
            elif node.op == '/':
                if right.is_constant() and right.offset != 0:
                    try:
                        inv = Fraction(1, 1) / (Fraction(str(right.offset)) if isinstance(right.offset, float) else Fraction(right.offset))
                        return left.mul_const(inv)
                    except Exception:
                        return None
        return None

    def _get_var_name(self, node: c_ast.Node) -> Optional[str]:
        if isinstance(node, c_ast.ID):
            return node.name
        elif isinstance(node, c_ast.StructRef):
            base = self._get_var_name(node.name)
            field = node.field.name if isinstance(node.field, c_ast.ID) else str(node.field)
            if base:
                op = "->" if node.type == "->" else "."
                return f"{base}{op}{field}"
        return None

    def _eval_c_expr(self, node: c_ast.Node, loop_var: str) -> Tuple[Optional[Union[int, float, Fraction]], Optional[str]]:
        if isinstance(node, c_ast.Constant):
            try:
                return int(node.value, 0), None
            except ValueError:
                try:
                    val_str = str(node.value).rstrip("fFlL")
                    frac = Fraction(val_str)
                    return (int(frac) if frac.denominator == 1 else frac), None
                except Exception:
                    return None, str(node.value)
        elif isinstance(node, c_ast.ID):
            if node.name == loop_var:
                return 0, loop_var
            if self.scope_env and node.name in self.scope_env:
                val = self.scope_env[node.name]
                if isinstance(val, (int, float, Fraction)):
                    return (int(val) if isinstance(val, Fraction) and val.denominator == 1 else val), None
            return None, node.name
        elif isinstance(node, c_ast.StructRef):
            var_name = self._get_var_name(node)
            return None, var_name
        elif isinstance(node, c_ast.UnaryOp):
            val, sym = self._eval_c_expr(node.expr, loop_var)
            if val is not None:
                if node.op == '-':
                    res = -val
                    return (int(res) if isinstance(res, Fraction) and res.denominator == 1 else res), None
                elif node.op == '+':
                    return val, None
            return None, f"({node.op}{sym})"
        elif isinstance(node, c_ast.BinaryOp):
            l_val, l_str = self._eval_c_expr(node.left, loop_var)
            r_val, r_str = self._eval_c_expr(node.right, loop_var)
            
            if l_val is not None and r_val is not None:
                if node.op == '+':
                    res = l_val + r_val
                    return (int(res) if isinstance(res, Fraction) and res.denominator == 1 else res), None
                elif node.op == '-':
                    res = l_val - r_val
                    return (int(res) if isinstance(res, Fraction) and res.denominator == 1 else res), None
                elif node.op == '*':
                    res = l_val * r_val
                    return (int(res) if isinstance(res, Fraction) and res.denominator == 1 else res), None
                elif node.op == '/':
                    if r_val != 0:
                        try:
                            frac = Fraction(str(l_val) if isinstance(l_val, float) else l_val,
                                            str(r_val) if isinstance(r_val, float) else r_val)
                            return (int(frac) if frac.denominator == 1 else frac), None
                        except Exception:
                            return l_val / r_val, None
            
            l_repr = str(l_val) if l_val is not None else l_str
            r_repr = str(r_val) if r_val is not None else r_str
            return None, f"({l_repr} {node.op} {r_repr})"
            
        return None, None

    def _add_delta(self, var_name: str, stride: Optional[int], dynamic_expr: Optional[str] = None):
        if var_name not in self.summary.var_exprs:
            self.summary.var_exprs[var_name] = VariableLoopExpr(var_name)
        if stride is not None:
            self.summary.var_exprs[var_name].add_term(LinearTerm(stride=stride))
        elif dynamic_expr:
            self.summary.var_exprs[var_name].add_term(LinearTerm(stride=1, scale_var=dynamic_expr))

    def _set_scale_kernel(self, var_name: str, kernel: ScaleKernel):
        if var_name not in self.summary.var_exprs:
            self.summary.var_exprs[var_name] = VariableLoopExpr(var_name)
        self.summary.var_exprs[var_name].scale_kernel = kernel

    def _extract_modulo_condition(self, cond_node: c_ast.Node, loop_var: str) -> Optional[Tuple[int, int, bool]]:
        """
        Extracts (period P, remainder r, is_equality) from conditions like:
        - (i % P == r) or (r == i % P)
        - (i % P != r)
        - !(i % P)
        - (i & mask == 0)
        """
        if isinstance(cond_node, c_ast.BinaryOp) and cond_node.op in ('==', '!='):
            is_eq = (cond_node.op == '==')
            left = cond_node.left
            right = cond_node.right

            if isinstance(left, c_ast.BinaryOp) and left.op in ('%', '&'):
                mod_op = left
                rem_node = right
            elif isinstance(right, c_ast.BinaryOp) and right.op in ('%', '&'):
                mod_op = right
                rem_node = left
            else:
                return None

            if self._get_var_name(mod_op.left) == loop_var:
                r_val, _ = self._eval_c_expr(rem_node, loop_var)
                if r_val is None:
                    return None

                if mod_op.op == '%':
                    p_val, _ = self._eval_c_expr(mod_op.right, loop_var)
                    if p_val and p_val > 0:
                        return p_val, r_val, is_eq
                elif mod_op.op == '&':
                    mask_val, _ = self._eval_c_expr(mod_op.right, loop_var)
                    if mask_val is not None and mask_val > 0 and (mask_val & (mask_val + 1)) == 0:
                        return mask_val + 1, r_val, is_eq

        elif isinstance(cond_node, c_ast.UnaryOp) and cond_node.op == '!':
            sub = cond_node.expr
            if isinstance(sub, c_ast.BinaryOp) and sub.op == '%':
                if self._get_var_name(sub.left) == loop_var:
                    p_val, _ = self._eval_c_expr(sub.right, loop_var)
                    if p_val and p_val > 0:
                        return p_val, 0, True

        return None

    def _extract_branch_deltas(self, stmts: List[c_ast.Node], loop_var: str) -> Dict[str, int]:
        deltas: Dict[str, int] = {}
        for s in stmts:
            if isinstance(s, c_ast.UnaryOp):
                v = self._get_var_name(s.expr)
                if v:
                    if s.op in ('p++', '++'):
                        deltas[v] = deltas.get(v, 0) + 1
                    elif s.op in ('p--', '--'):
                        deltas[v] = deltas.get(v, 0) - 1
            elif isinstance(s, c_ast.Assignment):
                v = self._get_var_name(s.lvalue)
                if v:
                    if s.op == '+=':
                        val, _ = self._eval_c_expr(s.rvalue, loop_var)
                        if val is not None:
                            deltas[v] = deltas.get(v, 0) + val
                    elif s.op == '-=':
                        val, _ = self._eval_c_expr(s.rvalue, loop_var)
                        if val is not None:
                            deltas[v] = deltas.get(v, 0) - val
                    elif s.op == '=':
                        aff = self._extract_affine_c_node(s.rvalue)
                        if aff is not None and aff.coeffs.get(v, 0) == 1:
                            deltas[v] = deltas.get(v, 0) + aff.offset
        return deltas

    def _handle_c_if_branch(self, if_node: c_ast.If, loop_var: str):
        mod_cond = self._extract_modulo_condition(if_node.cond, loop_var)
        if not mod_cond:
            self.summary.has_unsupported_ops = True
            return

        P, remainder, is_equality = mod_cond
        true_stmts = if_node.iftrue.block_items if isinstance(if_node.iftrue, c_ast.Compound) else [if_node.iftrue]
        false_stmts = []
        if if_node.iffalse:
            false_stmts = if_node.iffalse.block_items if isinstance(if_node.iffalse, c_ast.Compound) else [if_node.iffalse]

        true_deltas = self._extract_branch_deltas(true_stmts, loop_var)
        false_deltas = self._extract_branch_deltas(false_stmts, loop_var)
        all_vars = set(true_deltas.keys()) | set(false_deltas.keys())

        if not all_vars:
            self.summary.has_unsupported_ops = True
            return

        for v in sorted(all_vars):
            d_true = true_deltas.get(v, 0)
            d_false = false_deltas.get(v, 0)
            pattern = []
            for k in range(P):
                matches = (k == remainder) if is_equality else (k != remainder)
                pattern.append(d_true if matches else d_false)

            if v not in self.summary.var_exprs:
                self.summary.var_exprs[v] = VariableLoopExpr(v)
            self.summary.var_exprs[v].add_term(PeriodicTerm(pattern=pattern))

    def _add_array_mutation(self, target_key: str, delta: int):
        n_len = self.summary.iterations or self.summary.symbolic_iterations
        self.summary.array_mutations[target_key] = ArraySliceMutation(
            target_array=target_key,
            slice_length=n_len,
            kind="accumulate",
            delta=delta
        )

    def _handle_c_array_mutation(self, stmt: c_ast.Assignment, loop_var: str, target_key: Optional[str] = None):
        if not target_key:
            if not isinstance(stmt.lvalue, c_ast.ArrayRef) or not isinstance(stmt.lvalue.name, c_ast.ID):
                self.summary.has_unsupported_ops = True
                return
            arr_name = stmt.lvalue.name.name
            subscript = stmt.lvalue.subscript

            is_sequential = isinstance(subscript, c_ast.ID) and subscript.name == loop_var
            if not is_sequential:
                logger.warning(
                    "[accelerate_c] Unstructured or non-sequential array write target for array '%s'. Gracefully falling back.",
                    arr_name
                )
                self.summary.has_unsupported_ops = True
                return
            target_key = arr_name

        n_len = self.summary.iterations or self.summary.symbolic_iterations
        if stmt.op == '=':
            aff = self._extract_affine_c_node(stmt.rvalue)
            if aff is not None:
                loop_coeff = aff.coeffs.get(loop_var, 0)
                other_coeffs = {k: v for k, v in aff.coeffs.items() if k != loop_var}
                if not other_coeffs:
                    if loop_coeff == 0:
                        self.summary.array_mutations[target_key] = ArraySliceMutation(
                            target_array=target_key,
                            slice_length=n_len,
                            kind="constant",
                            constant_val=aff.offset
                        )
                        return
                    else:
                        self.summary.array_mutations[target_key] = ArraySliceMutation(
                            target_array=target_key,
                            slice_length=n_len,
                            kind="affine",
                            base=aff.offset,
                            stride=loop_coeff
                        )
                        return
        elif stmt.op in ('+=', '-='):
            delta_val, _ = self._eval_c_expr(stmt.rvalue, loop_var)
            if delta_val is not None:
                if stmt.op == '-=':
                    delta_val = -delta_val
                self.summary.array_mutations[target_key] = ArraySliceMutation(
                    target_array=target_key,
                    slice_length=n_len,
                    kind="accumulate",
                    delta=delta_val
                )
                return

        logger.warning(
            "[accelerate_c] Complex non-linear array value expression for target '%s'. Gracefully falling back.",
            target_key
        )
        self.summary.has_unsupported_ops = True
