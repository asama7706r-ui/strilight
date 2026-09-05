"""
Strilight Python Loop Lifter (strilight.frontend.python.lifter)
==============================================================
Extracts mathematical loop summaries directly from Python AST nodes and source code.
"""

import ast
from fractions import Fraction
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

from strilight.engine.vsa.models import (
    VariableLoopExpr,
    LoopSummary,
    LinearTerm,
    PeriodicTerm,
    AffineExpr,
    VariableCouplingMatrix,
    ArrayDescriptor,
    ArraySliceMutation,
)
from strilight.frontend.base import BaseLanguageLifter

logger = logging.getLogger(__name__)


class PythonLoopLifter(ast.NodeVisitor, BaseLanguageLifter):
    """
    AST visitor that extracts induction variables, state updates, coupled
    linear recurrences, and scope-aware array table lookups from Python loops.
    """

    def __init__(self, scope_env: Optional[Dict[str, Any]] = None):
        self.summary = LoopSummary()
        self.loop_found = False
        self.scope_env = dict(scope_env) if scope_env else {}
        self._register_scope_arrays(self.scope_env)

    def _register_scope_arrays(self, env: Dict[str, Any]):
        for name, val in env.items():
            if isinstance(val, (list, tuple)) and len(val) > 0 and all(isinstance(x, (int, float, Fraction)) for x in val):
                if name not in self.summary.array_descriptors:
                    self.summary.array_descriptors[name] = ArrayDescriptor(
                        name, len(val), elements=[int(x) if isinstance(x, Fraction) and x.denominator == 1 else int(x) for x in val]
                    )

    def _extract_scope_arrays(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            elements = []
                            is_num = True
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, (int, float, Fraction)):
                                    elements.append(int(elt.value) if isinstance(elt.value, Fraction) and elt.value.denominator == 1 else int(elt.value))
                                elif isinstance(elt, ast.UnaryOp) and isinstance(elt.op, ast.USub) and isinstance(elt.operand, ast.Constant) and isinstance(elt.operand.value, (int, float, Fraction)):
                                    neg = -elt.operand.value
                                    elements.append(int(neg) if isinstance(neg, Fraction) and neg.denominator == 1 else int(neg))
                                else:
                                    is_num = False
                                    break
                            if is_num and len(elements) > 0:
                                self.summary.array_descriptors[name] = ArrayDescriptor(
                                    name, len(elements), elements=elements
                                )

    def lift(self, source_or_ast: Union[str, ast.AST]) -> LoopSummary:
        if isinstance(source_or_ast, str):
            tree = ast.parse(source_or_ast)
        else:
            tree = source_or_ast

        self._extract_scope_arrays(tree)
        self.visit(tree)
        return self.summary

    def visit_For(self, node: ast.For):
        if not self.loop_found:
            self.loop_found = True
            # Extract loop iteration count N
            n_iters, symbolic_n = self._extract_range_iterations(node.iter)
            self.summary.iterations = n_iters
            self.summary.symbolic_iterations = symbolic_n
            self._analyze_body(node.body, loop_var=getattr(node.target, 'id', 'i'))
        else:
            self.generic_visit(node)

    def _extract_range_iterations(self, iter_node: ast.AST) -> Tuple[Optional[int], Optional[str]]:
        if isinstance(iter_node, ast.Call) and getattr(iter_node.func, 'id', '') == 'range':
            args = iter_node.args
            if len(args) == 1:
                if isinstance(args[0], ast.Constant):
                    return int(args[0].value), None
                elif isinstance(args[0], ast.Name):
                    return None, args[0].id
            elif len(args) == 2:
                if isinstance(args[0], ast.Constant) and isinstance(args[1], ast.Constant):
                    return int(args[1].value) - int(args[0].value), None
                elif isinstance(args[1], ast.Name):
                    return None, args[1].id
        return None, None

    def _analyze_body(self, body_nodes: List[ast.AST], loop_var: str):
        # Check for multi-variable coupled recurrence first
        coupled_mat = self._detect_coupled_system(body_nodes)
        if coupled_mat:
            self.summary.coupling_matrix = coupled_mat
            for v in coupled_mat.vars:
                if v not in self.summary.var_exprs:
                    self.summary.var_exprs[v] = VariableLoopExpr(v)
            return

        for stmt in body_nodes:
            if isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    var_name = stmt.target.id
                    if isinstance(stmt.op, ast.Add):
                        p_term = self._detect_array_subscript_term(stmt.value, loop_var)
                        if p_term is not None:
                            self._add_periodic_term(var_name, p_term)
                        else:
                            stride = self._eval_simple_expr(stmt.value)
                            if stride is not None:
                                self._add_linear_delta(var_name, stride)
                    elif isinstance(stmt.op, ast.Sub):
                        p_term = self._detect_array_subscript_term(stmt.value, loop_var)
                        if p_term is not None:
                            neg_pattern = [-x for x in p_term.pattern]
                            neg_term = PeriodicTerm(neg_pattern, scale_var=p_term.scale_var)
                            self._add_periodic_term(var_name, neg_term)
                        else:
                            stride = self._eval_simple_expr(stmt.value)
                            if stride is not None:
                                self._add_linear_delta(var_name, -stride)
                elif isinstance(stmt.target, ast.Subscript):
                    self._handle_array_mutation_augassign(stmt, loop_var)

            elif isinstance(stmt, ast.Assign):
                if len(stmt.targets) == 1:
                    target = stmt.targets[0]
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
                            if isinstance(stmt.value.left, ast.Name) and stmt.value.left.id == var_name:
                                p_term = self._detect_array_subscript_term(stmt.value.right, loop_var)
                                if p_term is not None:
                                    self._add_periodic_term(var_name, p_term)
                            elif isinstance(stmt.value.right, ast.Name) and stmt.value.right.id == var_name:
                                p_term = self._detect_array_subscript_term(stmt.value.left, loop_var)
                                if p_term is not None:
                                    self._add_periodic_term(var_name, p_term)
                    elif isinstance(target, ast.Subscript):
                        self._handle_array_mutation_assign(stmt, loop_var)

            elif isinstance(stmt, ast.For):
                # Nested Python loop
                inner_lifter = PythonLoopLifter(scope_env=self.scope_env)
                inner_lifter.summary.array_descriptors.update(self.summary.array_descriptors)
                inner_summary = inner_lifter.lift(ast.Module(body=[stmt], type_ignores=[]))
                inner_n = inner_summary.iterations or 1
                for v, expr in inner_summary.var_exprs.items():
                    for t in expr.terms:
                        if isinstance(t, LinearTerm):
                            self._add_linear_delta(v, t.stride * inner_n)
                        elif isinstance(t, PeriodicTerm):
                            self._add_periodic_term(v, t)

    def _detect_coupled_system(self, body_nodes: List[ast.AST]) -> Optional[VariableCouplingMatrix]:
        temp_map: Dict[str, AffineExpr] = {}
        final_assigns: Dict[str, AffineExpr] = {}
        temp_vars = set()

        def _substitute(expr: AffineExpr, state: Dict[str, AffineExpr]) -> AffineExpr:
            res = AffineExpr({}, offset=expr.offset)
            for reg, coeff in expr.coeffs.items():
                if reg in state:
                    res = res.add(state[reg].mul_const(coeff))
                else:
                    res = res.add(AffineExpr({reg: coeff}))
            return res

        for stmt in body_nodes:
            if isinstance(stmt, ast.Assign):
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    target_name = stmt.targets[0].id
                    if isinstance(stmt.value, ast.Name) and stmt.value.id in temp_map:
                        final_assigns[target_name] = temp_map[stmt.value.id]
                        temp_vars.add(stmt.value.id)
                    else:
                        aff = self._extract_affine_py_node(stmt.value)
                        if aff:
                            sub_aff = _substitute(aff, final_assigns)
                            temp_map[target_name] = sub_aff
                            final_assigns[target_name] = sub_aff
                elif len(stmt.targets) == 1 and isinstance(stmt.targets[0], (ast.Tuple, ast.List)):
                    t_names = [elt.id for elt in stmt.targets[0].elts if isinstance(elt, ast.Name)]
                    if isinstance(stmt.value, (ast.Tuple, ast.List)):
                        val_nodes = stmt.value.elts
                        for t_name, val_node in zip(t_names, val_nodes):
                            if isinstance(val_node, ast.Name) and val_node.id in temp_map:
                                final_assigns[t_name] = temp_map[val_node.id]
                                temp_vars.add(val_node.id)
                            else:
                                aff = self._extract_affine_py_node(val_node)
                                if aff:
                                    sub_aff = _substitute(aff, final_assigns)
                                    temp_map[t_name] = sub_aff
                                    final_assigns[t_name] = sub_aff
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                target_name = stmt.target.id
                aff = self._extract_affine_py_node(stmt.value)
                if aff:
                    sub_aff = _substitute(aff, final_assigns)
                    prev_expr = final_assigns.get(target_name, AffineExpr.from_reg(target_name))
                    if isinstance(stmt.op, ast.Add):
                        new_expr = prev_expr.add(sub_aff)
                    elif isinstance(stmt.op, ast.Sub):
                        new_expr = prev_expr.sub(sub_aff)
                    else:
                        new_expr = None
                    if new_expr:
                        temp_map[target_name] = new_expr
                        final_assigns[target_name] = new_expr

        # Filter out intermediate temporary variables (e.g. next_a, next_b)
        for t_var in temp_vars:
            final_assigns.pop(t_var, None)

        if len(final_assigns) >= 2:
            vars_list = sorted(final_assigns.keys())
            mat = VariableCouplingMatrix(vars_list)
            for v in vars_list:
                mat.set_affine_row(v, final_assigns[v])

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

    def _extract_affine_py_node(self, node: ast.AST) -> Optional[AffineExpr]:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, Fraction)):
            return AffineExpr.from_const(node.value)
        elif isinstance(node, ast.Name):
            if self.scope_env and node.id in self.scope_env:
                val = self.scope_env[node.id]
                if isinstance(val, (int, float, Fraction)):
                    return AffineExpr.from_const(val)
            return AffineExpr.from_reg(node.id)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            sub = self._extract_affine_py_node(node.operand)
            return sub.mul_const(-1) if sub else None
        elif isinstance(node, ast.BinOp):
            left = self._extract_affine_py_node(node.left)
            right = self._extract_affine_py_node(node.right)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left.add(right)
            elif isinstance(node.op, ast.Sub):
                return left.sub(right)
            elif isinstance(node.op, ast.Mult):
                if left.is_constant():
                    return right.mul_const(left.offset)
                elif right.is_constant():
                    return left.mul_const(right.offset)
            elif isinstance(node.op, ast.Div):
                if right.is_constant() and right.offset != 0:
                    try:
                        inv = Fraction(1, 1) / (Fraction(str(right.offset)) if isinstance(right.offset, float) else Fraction(right.offset))
                        return left.mul_const(inv)
                    except Exception:
                        return None
        return None

    def _add_linear_delta(self, var_name: str, stride: int):
        if var_name not in self.summary.var_exprs:
            self.summary.var_exprs[var_name] = VariableLoopExpr(var_name)
        self.summary.var_exprs[var_name].add_term(LinearTerm(stride=stride))

    def _add_periodic_term(self, var_name: str, term: PeriodicTerm):
        if var_name not in self.summary.var_exprs:
            self.summary.var_exprs[var_name] = VariableLoopExpr(var_name)
        self.summary.var_exprs[var_name].add_term(term)
        self.summary.patterns[var_name] = term.pattern

    def _detect_array_subscript_term(self, node: ast.AST, loop_var: str) -> Optional[PeriodicTerm]:
        """
        Detects if an AST node is an array subscript like `table[i % P]` or `table[(i * s) & mask]`,
        intersects its index interval with array bounds, and extracts the cycle pattern as a PeriodicTerm.
        """
        from strilight.engine.domains import StridedInterval

        subscript_node = None
        scale_factor = 1
        scale_var = None

        if isinstance(node, ast.Subscript):
            subscript_node = node
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            if isinstance(node.left, ast.Subscript):
                subscript_node = node.left
                if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float, Fraction)):
                    scale_factor = int(node.right.value)
                elif isinstance(node.right, ast.Name):
                    scale_var = node.right.id
            elif isinstance(node.right, ast.Subscript):
                subscript_node = node.right
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, (int, float, Fraction)):
                    scale_factor = int(node.left.value)
                elif isinstance(node.left, ast.Name):
                    scale_var = node.left.id

        if not subscript_node or not isinstance(subscript_node.value, ast.Name):
            return None

        arr_name = subscript_node.value.id
        desc = self.summary.array_descriptors.get(arr_name)
        if not desc or not desc.elements:
            return None

        slice_node = subscript_node.slice

        # Determine cycle period P and whether the slice uses loop_var
        P = None
        is_cyclic = False

        if isinstance(slice_node, ast.BinOp):
            if isinstance(slice_node.op, ast.Mod) and isinstance(slice_node.right, ast.Constant):
                P = int(slice_node.right.value)
                is_cyclic = True
            elif isinstance(slice_node.op, ast.BitAnd) and isinstance(slice_node.right, ast.Constant):
                mask = int(slice_node.right.value)
                if (mask & (mask + 1)) == 0 and mask > 0:
                    P = mask + 1
                    is_cyclic = True

        if not is_cyclic:
            if isinstance(slice_node, ast.Name) and slice_node.id == loop_var:
                P = desc.length
                is_cyclic = True
            elif isinstance(slice_node, ast.BinOp) and isinstance(slice_node.op, ast.Add):
                # Out-of-bounds check (e.g. table[i + 50])
                try:
                    compiled_expr = compile(ast.Expression(slice_node), "<subscript_slice>", "eval")
                    indices = [int(eval(compiled_expr, {}, {loop_var: k})) for k in range(min(self.summary.iterations or 5, 5))]
                    idx_interval = StridedInterval(min(indices), max(indices), bit_width=64, stride=1)
                    desc.intersect_index(idx_interval)
                except Exception:
                    pass
                return None

        if not is_cyclic or P is None or P <= 0:
            return None

        # Safely evaluate index for k in range(P)
        indices = []
        try:
            compiled_expr = compile(ast.Expression(slice_node), "<subscript_slice>", "eval")
            for k in range(P):
                val = eval(compiled_expr, {}, {loop_var: k})
                indices.append(int(val))
        except Exception:
            return None

        min_idx = min(indices)
        max_idx = max(indices)
        idx_interval = StridedInterval(min_idx, max_idx, bit_width=64, stride=1)
        desc.intersect_index(idx_interval)

        pattern = []
        for idx in indices:
            elem = desc.elements[idx % desc.length]
            pattern.append(int(elem * scale_factor))

        return PeriodicTerm(pattern, scale_var=scale_var)

    def _eval_simple_expr(self, expr_node: ast.AST) -> Optional[Union[int, Fraction]]:
        if isinstance(expr_node, ast.Constant):
            if isinstance(expr_node.value, int):
                return expr_node.value
            elif isinstance(expr_node.value, float):
                frac = Fraction(str(expr_node.value))
                return int(frac) if frac.denominator == 1 else frac
            elif isinstance(expr_node.value, Fraction):
                return int(expr_node.value) if expr_node.value.denominator == 1 else expr_node.value
            return expr_node.value
        elif isinstance(expr_node, ast.Name):
            if self.scope_env and expr_node.id in self.scope_env:
                val = self.scope_env[expr_node.id]
                if isinstance(val, (int, float, Fraction)):
                    frac = Fraction(str(val)) if isinstance(val, float) else Fraction(val)
                    return int(frac) if frac.denominator == 1 else frac
        elif isinstance(expr_node, ast.BinOp):
            left = self._eval_simple_expr(expr_node.left)
            right = self._eval_simple_expr(expr_node.right)
            if left is not None and right is not None:
                if isinstance(expr_node.op, ast.Add): return left + right
                elif isinstance(expr_node.op, ast.Sub): return left - right
                elif isinstance(expr_node.op, ast.Mult): return left * right
                elif isinstance(expr_node.op, ast.Div):
                    frac = Fraction(left) / Fraction(right)
                    return int(frac) if frac.denominator == 1 else frac
        return None

    def _handle_array_mutation_assign(self, stmt: ast.Assign, loop_var: str):
        target = stmt.targets[0]
        if not isinstance(target.value, ast.Name):
            self.summary.has_unsupported_ops = True
            return

        arr_name = target.value.id
        slice_node = target.slice

        # 1. Check index regularity: must be direct sequential counter (e.g. arr[i] = ...)
        is_sequential = isinstance(slice_node, ast.Name) and slice_node.id == loop_var
        if not is_sequential:
            logger.warning(
                "[accelerate] Unstructured or non-sequential array write target for array '%s'. Gracefully falling back to native loop.",
                arr_name
            )
            self.summary.has_unsupported_ops = True
            return

        # 2. Mathematical Finite Difference Analysis of value expression
        try:
            compiled_val = compile(ast.Expression(stmt.value), "<array_val>", "eval")
            y0 = eval(compiled_val, {}, {loop_var: 0})
            y1 = eval(compiled_val, {}, {loop_var: 1})
            y2 = eval(compiled_val, {}, {loop_var: 2})

            if isinstance(y0, (int, float, Fraction)) and isinstance(y1, (int, float, Fraction)) and isinstance(y2, (int, float, Fraction)):
                d1 = int(y1 - y0)
                d2 = int((y2 - y1) - (y1 - y0))

                if d1 == 0:
                    # Constant value mutation: arr[i] = const
                    self.summary.array_mutations[arr_name] = ArraySliceMutation(
                        target_array=arr_name,
                        slice_length=self.summary.iterations or self.summary.symbolic_iterations,
                        kind="constant",
                        constant_val=int(y0)
                    )
                    return
                elif d2 == 0:
                    # Affine progression mutation: arr[i] = base + i * stride
                    self.summary.array_mutations[arr_name] = ArraySliceMutation(
                        target_array=arr_name,
                        slice_length=self.summary.iterations or self.summary.symbolic_iterations,
                        kind="affine",
                        base=int(y0),
                        stride=d1
                    )
                    return
        except Exception:
            pass

        logger.warning(
            "[accelerate] Complex non-linear array value expression for array '%s'. Gracefully falling back to native loop.",
            arr_name
        )
        self.summary.has_unsupported_ops = True

    def _handle_array_mutation_augassign(self, stmt: ast.AugAssign, loop_var: str):
        target = stmt.target
        if not isinstance(target.value, ast.Name):
            self.summary.has_unsupported_ops = True
            return

        arr_name = target.value.id
        slice_node = target.slice

        is_sequential = isinstance(slice_node, ast.Name) and slice_node.id == loop_var
        if not is_sequential:
            logger.warning(
                "[accelerate] Unstructured or non-sequential array write target for array '%s'. Gracefully falling back to native loop.",
                arr_name
            )
            self.summary.has_unsupported_ops = True
            return

        delta = self._eval_simple_expr(stmt.value)
        if delta is not None:
            if isinstance(stmt.op, ast.Sub):
                delta = -delta
            self.summary.array_mutations[arr_name] = ArraySliceMutation(
                target_array=arr_name,
                slice_length=self.summary.iterations or self.summary.symbolic_iterations,
                kind="accumulate",
                delta=delta
            )
        else:
            logger.warning(
                "[accelerate] Non-constant accumulator for array '%s'. Gracefully falling back to native loop.",
                arr_name
            )
            self.summary.has_unsupported_ops = True
