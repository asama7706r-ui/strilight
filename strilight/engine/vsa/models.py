from __future__ import annotations
import copy
from fractions import Fraction
import logging
from typing import Dict, Optional, List, Any, Tuple, Callable, Set, Union, TYPE_CHECKING

try:
    import z3
except ImportError:
    z3 = None

if TYPE_CHECKING:
    from strilight.extensions.tracker import TraceRecord

logger = logging.getLogger("strilight.engine.vsa.models")


# ============================================================================
# 1. Multiplicative Scale Kernels: A(N)
# ============================================================================

class ScaleKernel:
    """
    Multiplicative Scale Kernel A(N) for The Grand Master Recurrence Equation:
        X(N) = A(N) * X_0 + Delta_total(N)
    """
    def to_smt(self, N_ast: z3.BitVecRef, bit_size: int = 64) -> z3.BitVecRef:
        raise NotImplementedError

    def to_induction_formula(self) -> str:
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


class IdentityScale(ScaleKernel):
    """A(N) = 1 (Multiplicative Identity)"""
    def to_smt(self, N_ast: z3.BitVecRef, bit_size: int = 64) -> z3.BitVecRef:
        return z3.BitVecVal(1, bit_size)

    def to_induction_formula(self) -> str:
        return "1"

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "identity", "scale": 1}


class PowerScale(ScaleKernel):
    """A(N) = base^N (Exponential Scaling, e.g. shl / rolling hash)"""
    def __init__(self, base: int = 2):
        self.base = base

    def to_smt(self, N_ast: z3.BitVecRef, bit_size: int = 64) -> z3.BitVecRef:
        if self.base == 2:
            return z3.BitVecVal(1, bit_size) << N_ast
        return z3.BitVecVal(self.base, bit_size) ** N_ast

    def to_induction_formula(self) -> str:
        return f"{self.base}^N"

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "power", "base": self.base}


# ============================================================================
# 2. Universal Additive Loop Terms: Term_k(N)
# ============================================================================

class LoopTerm:
    """
    Base Abstract Class for an Additive Component in the Grand Master Equation:
        Delta_total(N) = sum_k Term_k(N)
    """
    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """Returns (term_at_N, term_at_N_prev) BitVector ASTs."""
        raise NotImplementedError

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


class LinearTerm(LoopTerm):
    """
    Scalar or Symbolic Stride Component:
        Delta_scalar(N) = stride * N (optionally * scale_var)
    """
    def __init__(self, stride: int = 1, scale_var: Optional[str] = None):
        self.stride = stride
        self.scale_var = scale_var

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        s_val = z3.BitVecVal(self.stride, bit_size)
        delta_n = s_val * N_ast
        delta_prev = s_val * N_prev_ast
        if self.scale_var:
            scale_ast = resolve_val_fn(self.scale_var)
            if scale_ast is not None:
                if scale_ast.size() != bit_size:
                    scale_ast = z3.ZeroExt(bit_size - scale_ast.size(), scale_ast)
                delta_n = delta_n * scale_ast
                delta_prev = delta_prev * scale_ast
        return delta_n, delta_prev

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        scale_suffix = f" * {self.scale_var}" if self.scale_var else ""
        return {
            "type": "linear",
            "delta": self.stride,
            "stride": self.stride,
            "scale_var": self.scale_var,
            "formula_at_N": f"{var_name}_0 + ({self.stride}) * N{scale_suffix}",
            "formula_at_N_minus_1": f"{var_name}_0 + ({self.stride}) * (N - 1){scale_suffix}"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "linear", "stride": self.stride, "scale_var": self.scale_var}


class PeriodicTerm(LoopTerm):
    """
    Polycyclic Table Stride Component:
        Delta_poly(N) = (N // P) * sum(P) + PrefixSum[N % P] (optionally * scale_var)
    """
    def __init__(self, pattern: List[int], scale_var: Optional[str] = None):
        self.pattern = list(pattern)
        self.scale_var = scale_var

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        from strilight.engine.vsa.smt_translator import LoopSMTTranslator
        poly_n = LoopSMTTranslator.build_polycyclic_delta_ast(N_ast, self.pattern, bit_size)
        poly_prev = LoopSMTTranslator.build_polycyclic_delta_ast(N_prev_ast, self.pattern, bit_size)
        if self.scale_var:
            scale_ast = resolve_val_fn(self.scale_var)
            if scale_ast is not None:
                if scale_ast.size() != bit_size:
                    scale_ast = z3.ZeroExt(bit_size - scale_ast.size(), scale_ast)
                poly_n = poly_n * scale_ast
                poly_prev = poly_prev * scale_ast
        return poly_n, poly_prev

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        P = len(self.pattern)
        P_sum = sum(self.pattern)
        scale_suffix = f" * {self.scale_var}" if self.scale_var else ""
        return {
            "type": "periodic",
            "pattern": self.pattern,
            "period": P,
            "cycle_sum": P_sum,
            "scale_var": self.scale_var,
            "formula_at_N": f"{var_name}_0 + (N // {P}) * {P_sum} + prefix_sum(N % {P}){scale_suffix}",
            "formula_at_N_minus_1": f"{var_name}_0 + ((N - 1) // {P}) * {P_sum} + prefix_sum((N - 1) % {P}){scale_suffix}"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "periodic", "pattern": self.pattern, "scale_var": self.scale_var}


class GeometricTerm(LoopTerm):
    """
    Geometric Shift Recurrence (Rule 6: Positional Receipt):
        Delta_geom(N) = sum_{i=0}^{N-1} base^i * var = ((base^N - 1) / (base - 1)) * var
    """
    def __init__(
        self,
        base: int = 2,
        var: Optional[str] = None,
        val: int = 1,
        modulo_bits: int = 0,
        iterations_bound: Optional[int] = None
    ):
        self.base = base
        self.var = var
        self.val = val
        self.modulo_bits = modulo_bits
        self.iterations_bound = iterations_bound

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        from strilight.engine.vsa.smt_translator import LoopSMTTranslator
        shift_info = {
            'base': self.base,
            'var': self.var,
            'val': self.val,
            'modulo_bits': self.modulo_bits
        }
        src_ast = resolve_val_fn(self.var) if self.var else None
        return LoopSMTTranslator.build_geometric_shift_ast(
            N_ast, N_prev_ast, shift_info, src_ast=src_ast, iterations_bound=self.iterations_bound
        )

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        src_desc = self.var or self.val
        return {
            "type": "geometric",
            "geometric_shift": {
                "base": self.base,
                "var": self.var,
                "val": self.val,
                "modulo_bits": self.modulo_bits
            },
            "base": self.base,
            "var": self.var,
            "val": self.val,
            "modulo_bits": self.modulo_bits,
            "formula_at_N": f"{var_name}_0 + ({self.base}^N - 1) * {src_desc}",
            "formula_at_N_minus_1": f"{var_name}_0 + ({self.base}^(N-1) - 1) * {src_desc}"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "geometric",
            "base": self.base,
            "var": self.var,
            "val": self.val,
            "modulo_bits": self.modulo_bits
        }


class TelescopingBranch:
    """
    Represents a single execution branch in a Telescoping Cascade.
    Contains the guard condition predicates, and the state transformations (deltas, expressions)
    occurring when this branch is taken.
    """
    def __init__(
        self,
        name: str = "branch",
        conditions: Optional[List[Dict[str, Any]]] = None,
        deltas: Optional[Dict[str, int]] = None,
        affine_exprs: Optional[Dict[str, 'AffineExpr']] = None,
        constant_sets: Optional[Dict[str, int]] = None,
    ):
        self.name = name
        # Conditions list: [{'lhs': 'eax', 'op': 'eq', 'rhs': 1, 'is_taken': True}, ...]
        self.conditions: List[Dict[str, Any]] = list(conditions or [])
        self.deltas: Dict[str, int] = dict(deltas or {})
        self.affine_exprs: Dict[str, 'AffineExpr'] = dict(affine_exprs or {})
        self.constant_sets: Dict[str, int] = dict(constant_sets or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "conditions": self.conditions,
            "deltas": self.deltas,
            "constant_sets": self.constant_sets,
        }


class TelescopingCascade:
    """
    The Telescoping Cascade for M Conditions (The Telescoping Partition of Unity).
    Represents an M-branch switch-case or nested if-elif-else cascade as a unified single-line
    linear equation without path explosion:
        Delta_total = sum_{k=1}^M (P_k * Delta_k)
    where:
        P_k = (prod_{j=1}^{k-1} (1 - c_j)) * c_k
        P_fallback = prod_{j=1}^{M-1} (1 - c_j)
    and sum_{k=1}^M P_k == 1.
    """
    def __init__(
        self,
        target_var: Optional[str] = None,
        branches: Optional[List[TelescopingBranch]] = None,
        target_reg: Optional[str] = None
    ):
        self.target_var = target_var or target_reg or ""
        self.branches: List[TelescopingBranch] = list(branches or [])

    @property
    def target_reg(self) -> str:
        return self.target_var

    @target_reg.setter
    def target_reg(self, val: str):
        self.target_var = val

    def add_branch(self, branch: TelescopingBranch) -> None:
        self.branches.append(branch)

    def is_partition_of_unity(self) -> bool:
        return len(self.branches) > 0

    def get_telescoping_formula(self) -> str:
        terms = []
        for k, b in enumerate(self.branches):
            d = b.deltas.get(self.target_var, 0)
            terms.append(f"P_{k+1}({b.name}) * ({d})")
        return " + ".join(terms) if terms else "0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_var": self.target_var,
            "target_reg": self.target_var,
            "branches": [b.to_dict() for b in self.branches],
            "telescoping_formula": self.get_telescoping_formula(),
            "partition_of_unity": self.is_partition_of_unity(),
        }


class TelescopingTerm(LoopTerm):
    """
    Telescoping Cascade Component for M Conditions:
        Delta_tele(N) = N * sum_{k=1}^M (P_k * Delta_k)
    """
    def __init__(self, cascade: TelescopingCascade, target_var: Optional[str] = None, target_reg: Optional[str] = None):
        self.cascade = cascade
        self.target_var = target_var or target_reg or cascade.target_var

    @property
    def target_reg(self) -> str:
        return self.target_var

    @target_reg.setter
    def target_reg(self, val: str):
        self.target_var = val

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        from strilight.engine.vsa.smt_translator import LoopSMTTranslator
        return LoopSMTTranslator.build_telescoping_cascade_ast(
            N_ast, N_prev_ast, self.target_var, self.cascade, resolve_val_fn=resolve_val_fn
        )

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        t_formula = self.cascade.get_telescoping_formula()
        return {
            "type": "telescoping",
            "telescoping_cascade": self.cascade.to_dict(),
            "formula_at_N": f"{var_name}_0 + ({t_formula}) * N",
            "formula_at_N_minus_1": f"{var_name}_0 + ({t_formula}) * (N - 1)"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "telescoping",
            "cascade": self.cascade.to_dict(),
            "target_var": self.target_var,
            "target_reg": self.target_var
        }


# ============================================================================
# 3. Universal Loop Expression Tree AST: VariableLoopExpr
# ============================================================================

class VariableLoopExpr:
    """
    Universal Loop Expression Tree AST for a Single Variable, Register, or Memory Target.
    Implements The Grand Master Recurrence Equation:
        X(N) = A(N) * X_0 + Delta_total(N)
    or
        X(N) = Constant (if constant_val is set).
    """
    def __init__(
        self,
        name: str,
        scale_kernel: Optional[ScaleKernel] = None,
        terms: Optional[List[LoopTerm]] = None,
        constant_val: Optional[int] = None,
        is_mem: bool = False,
        mem_addr: Optional[int] = None,
        mem_size_bits: int = 64
    ):
        self.name = name
        self.scale_kernel: ScaleKernel = scale_kernel or IdentityScale()
        self.terms: List[LoopTerm] = list(terms or [])
        self.constant_val: Optional[int] = constant_val
        self.is_mem = is_mem
        self.mem_addr = mem_addr
        self.mem_size_bits = mem_size_bits

    def add_term(self, term: LoopTerm) -> 'VariableLoopExpr':
        self.terms.append(term)
        return self

    def set_constant(self, val: int) -> 'VariableLoopExpr':
        self.constant_val = val
        self.terms.clear()
        self.scale_kernel = IdentityScale()
        return self

    def set_scale(self, scale_kernel: ScaleKernel) -> 'VariableLoopExpr':
        self.scale_kernel = scale_kernel
        return self

    def get_scalar_stride(self) -> Optional[int]:
        """Returns the scalar stride if this expression consists solely of a linear term."""
        if self.constant_val is not None:
            return None
        linear_terms = [t for t in self.terms if isinstance(t, LinearTerm)]
        if len(linear_terms) == 1 and len(self.terms) == 1:
            return linear_terms[0].stride
        return None

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef, z3.BitVecRef, z3.BitVecRef]:
        """
        Returns (scale_n, scale_prev, total_delta_n, total_delta_prev)
        """
        if self.constant_val is not None:
            c_ast = z3.BitVecVal(self.constant_val, bit_size)
            return z3.BitVecVal(0, bit_size), z3.BitVecVal(0, bit_size), c_ast, c_ast

        scale_n = self.scale_kernel.to_smt(N_ast, bit_size)
        scale_prev = self.scale_kernel.to_smt(N_prev_ast, bit_size)

        total_delta_n = z3.BitVecVal(0, bit_size)
        total_delta_prev = z3.BitVecVal(0, bit_size)

        for term in self.terms:
            t_n, t_prev = term.to_smt(N_ast, N_prev_ast, resolve_val_fn, bit_size)
            total_delta_n = total_delta_n + t_n
            total_delta_prev = total_delta_prev + t_prev

        return scale_n, scale_prev, total_delta_n, total_delta_prev

    def to_induction_formula(self) -> Dict[str, Any]:
        if self.constant_val is not None:
            return {
                "constant": self.constant_val,
                "formula_at_N": str(self.constant_val),
                "formula_at_N_minus_1": str(self.constant_val)
            }
        if len(self.terms) == 1:
            term_dict = self.terms[0].to_induction_formula(self.name)
            term_dict["scale"] = self.scale_kernel.to_induction_formula()
            return term_dict

        formulas = [t.to_induction_formula(self.name) for t in self.terms]
        return {
            "name": self.name,
            "scale": self.scale_kernel.to_induction_formula(),
            "terms": formulas,
            "formula_at_N": " + ".join(f.get("formula_at_N", "") for f in formulas) if formulas else f"{self.name}_0",
            "formula_at_N_minus_1": " + ".join(f.get("formula_at_N_minus_1", "") for f in formulas) if formulas else f"{self.name}_0"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "scale": self.scale_kernel.to_dict(),
            "terms": [t.to_dict() for t in self.terms],
            "constant_val": self.constant_val,
            "is_mem": self.is_mem,
            "mem_addr": self.mem_addr,
            "mem_size_bits": self.mem_size_bits
        }

    def to_python_expr(self, N_var: str = "N") -> str:
        """Emits an O(1) Python mathematical expression string."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_python_expr_str(self, N_var=N_var)

    def to_c_expr(self, N_var: str = "N") -> str:
        """Emits an O(1) C mathematical expression string."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_c_expr_str(self, N_var=N_var)


# Alias for backward compatibility
RegisterLoopExpr = VariableLoopExpr


# ============================================================================
# 4. Affine Expressions & Coupling Matrix (Rule 7)
# ============================================================================

def _to_frac(val: Any) -> Fraction:
    """Converts int, float, or Fraction to an exact Fraction."""
    if isinstance(val, Fraction):
        return val
    if isinstance(val, int):
        return Fraction(val, 1)
    if isinstance(val, float):
        return Fraction(str(val))
    return Fraction(val)

def _normalize_num(val: Union[int, float, Fraction]) -> Union[int, float, Fraction]:
    """
    Normalizes exact fractions with denominator == 1 to Python int for maximum backward
    compatibility, and cleans integer floats.
    """
    if isinstance(val, Fraction):
        if val.denominator == 1:
            return val.numerator
        return val
    elif isinstance(val, float):
        if val.is_integer():
            return int(val)
        frac = Fraction(str(val))
        if frac.denominator == 1:
            return frac.numerator
        return frac
    return val

class AffineExpr:
    """
    Represents an affine symbolic linear combination of registers and integer/rational offsets:
        Expr = sum(coeff * reg) + offset
    """
    def __init__(self, coeffs: Optional[Dict[str, Union[int, float, Fraction]]] = None, offset: Union[int, float, Fraction] = 0):
        self.coeffs: Dict[str, Union[int, float, Fraction]] = {
            k: _normalize_num(v) for k, v in (coeffs or {}).items() if v != 0
        }
        self.offset: Union[int, float, Fraction] = _normalize_num(offset)

    @classmethod
    def from_reg(cls, reg: str) -> 'AffineExpr':
        return cls(coeffs={reg: 1}, offset=0)

    @classmethod
    def from_const(cls, val: Union[int, float, Fraction]) -> 'AffineExpr':
        return cls(coeffs={}, offset=_normalize_num(val))

    def add(self, other: 'AffineExpr') -> 'AffineExpr':
        new_coeffs = dict(self.coeffs)
        for k, v in other.coeffs.items():
            new_val = _normalize_num(new_coeffs.get(k, 0) + v)
            if new_val == 0:
                new_coeffs.pop(k, None)
            else:
                new_coeffs[k] = new_val
        return AffineExpr(new_coeffs, _normalize_num(self.offset + other.offset))

    def sub(self, other: 'AffineExpr') -> 'AffineExpr':
        new_coeffs = dict(self.coeffs)
        for k, v in other.coeffs.items():
            new_val = _normalize_num(new_coeffs.get(k, 0) - v)
            if new_val == 0:
                new_coeffs.pop(k, None)
            else:
                new_coeffs[k] = new_val
        return AffineExpr(new_coeffs, _normalize_num(self.offset - other.offset))

    def mul_const(self, k: Union[int, float, Fraction]) -> 'AffineExpr':
        norm_k = _normalize_num(k)
        if norm_k == 0:
            return AffineExpr({}, 0)
        new_coeffs = {reg: _normalize_num(c * norm_k) for reg, c in self.coeffs.items()}
        return AffineExpr(new_coeffs, _normalize_num(self.offset * norm_k))

    def __add__(self, other):
        if isinstance(other, AffineExpr):
            return self.add(other)
        elif isinstance(other, (int, float, Fraction)):
            return AffineExpr(self.coeffs, self.offset + other)
        return NotImplemented

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, AffineExpr):
            return self.sub(other)
        elif isinstance(other, (int, float, Fraction)):
            return AffineExpr(self.coeffs, self.offset - other)
        return NotImplemented

    def __truediv__(self, other):
        if isinstance(other, (int, float, Fraction)):
            if other == 0:
                raise ZeroDivisionError("division by zero in AffineExpr")
            frac_other = Fraction(str(other)) if isinstance(other, float) else Fraction(other)
            return self.mul_const(Fraction(1, 1) / frac_other)
        return NotImplemented

    def __rsub__(self, other):
        if isinstance(other, (int, float, Fraction)):
            return self.mul_const(-1).add(AffineExpr.from_const(other))
        return NotImplemented

    def __mul__(self, other):
        if isinstance(other, (int, float, Fraction)):
            return self.mul_const(other)
        return NotImplemented

    def __rmul__(self, other):
        return self.__mul__(other)

    def is_constant(self) -> bool:
        return len(self.coeffs) == 0

    def is_pure_reg(self, reg: str) -> bool:
        return len(self.coeffs) == 1 and self.coeffs.get(reg) == 1 and self.offset == 0

    def get_scalar_delta(self, reg: str) -> Optional[Union[int, float, Fraction]]:
        """If this expression evaluates to `reg + c`, returns scalar delta `c`."""
        if len(self.coeffs) == 1 and self.coeffs.get(reg) == 1:
            return self.offset
        return None

    def __repr__(self) -> str:
        parts = [f"{c}*{r}" if c != 1 else r for r, c in self.coeffs.items()]
        if self.offset != 0 or not parts:
            parts.append(str(self.offset))
        return " + ".join(parts)


class VariableCouplingMatrix:
    """
    Rule 7: Vector State Space and Coupling Matrix (A_coupling).
    Represents the affine state transition across multiple coupled variables:
        V_{k+1} = A * V_k + B
    """
    def __init__(self, vars: List[str]):
        self.vars = list(vars)
        self.var_to_idx = {v: i for i, v in enumerate(self.vars)}
        self.regs = self.vars  # alias for backward compatibility
        self.reg_to_idx = self.var_to_idx
        self.dim = len(self.vars)
        # Identity matrix initially
        self.matrix = [[1 if i == j else 0 for j in range(self.dim)] for i in range(self.dim)]
        self.offset = [0] * self.dim

    def set_affine_row(self, var: str, expr: AffineExpr):
        if var not in self.var_to_idx:
            return
        row = self.var_to_idx[var]
        for j in range(self.dim):
            self.matrix[row][j] = 0
        for src_var, coeff in expr.coeffs.items():
            if src_var in self.var_to_idx:
                self.matrix[row][self.var_to_idx[src_var]] = coeff
        self.offset[row] = expr.offset

    def is_identity(self) -> bool:
        for i in range(self.dim):
            for j in range(self.dim):
                expected = 1 if i == j else 0
                if self.matrix[i][j] != expected:
                    return False
        for off in self.offset:
            if off != 0:
                return False
        return True

    def to_augmented_matrix(self) -> List[List[Union[int, float, Fraction]]]:
        """Returns the (dim+1) x (dim+1) augmented transition matrix [A | B ; 0 | 1]."""
        aug = []
        for i in range(self.dim):
            row = list(self.matrix[i]) + [self.offset[i]]
            aug.append(row)
        aug.append([0] * self.dim + [1])
        return aug

    def pow_mod(self, p: int, mod: Optional[int] = 2**32) -> 'VariableCouplingMatrix':
        """
        Computes (A_coupling)^p in O(log p) steps via Binary Matrix Exponentiation.
        When matrix entries are exact fractions/floats, performs exact arithmetic over Q.
        When entries are purely integer, performs standard modular arithmetic mod `mod`.
        """
        aug = self.to_augmented_matrix()
        n = len(aug)
        has_rational = any(isinstance(x, (Fraction, float)) for row in aug for x in row)

        def _mat_mul(A, B):
            C = [[0] * n for _ in range(n)]
            for i in range(n):
                for j in range(n):
                    s = 0
                    for k in range(n):
                        s += A[i][k] * B[k][j]
                    if has_rational or mod is None:
                        C[i][j] = _normalize_num(s)
                    else:
                        C[i][j] = s % mod
            return C

        res = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
        base = [[aug[i][j] if (has_rational or mod is None) else (aug[i][j] % mod) for j in range(n)] for i in range(n)]

        power = p
        while power > 0:
            if power % 2 == 1:
                res = _mat_mul(res, base)
            base = _mat_mul(base, base)
            power //= 2

        result_matrix = VariableCouplingMatrix(self.vars)
        for i in range(self.dim):
            for j in range(self.dim):
                result_matrix.matrix[i][j] = res[i][j]
            result_matrix.offset[i] = res[i][self.dim]

        return result_matrix

    def decompose_block_diagonal(self) -> List['VariableCouplingMatrix']:
        """
        Decomposes this global coupling matrix into independent block-diagonal matrices (Rule 14):
            A_global = A_1 (+) A_2 (+) ... (+) A_M
        Constructs an undirected dependency graph among variables and extracts connected components.
        If all variables are coupled, returns [self].
        If independent variable clusters exist (e.g. {x, vx} and {y, vy}), returns a list of
        smaller, completely decoupled VariableCouplingMatrix instances.
        """
        if self.dim <= 1:
            return [self]

        # 1. Build adjacency list of variable interactions
        adj: Dict[str, set] = {v: set() for v in self.vars}
        for i in range(self.dim):
            u = self.vars[i]
            for j in range(self.dim):
                v = self.vars[j]
                if i != j and self.matrix[i][j] != 0:
                    adj[u].add(v)
                    adj[v].add(u)

        # 2. Extract connected components using BFS/DFS
        visited = set()
        components: List[List[str]] = []
        for v in self.vars:
            if v not in visited:
                comp = []
                queue = [v]
                visited.add(v)
                while queue:
                    curr = queue.pop(0)
                    comp.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                # Preserve original variable order within component
                comp_sorted = [x for x in self.vars if x in comp]
                components.append(comp_sorted)

        # If only 1 component, the matrix is fully coupled (monolithic block)
        if len(components) <= 1:
            return [self]

        # 3. Create decoupled sub-matrices for each component
        sub_matrices: List['VariableCouplingMatrix'] = []
        for comp_vars in components:
            sub_mat = VariableCouplingMatrix(comp_vars)
            for sub_i, var in enumerate(comp_vars):
                orig_i = self.var_to_idx[var]
                for sub_j, src_var in enumerate(comp_vars):
                    orig_j = self.var_to_idx[src_var]
                    sub_mat.matrix[sub_i][sub_j] = self.matrix[orig_i][orig_j]
                sub_mat.offset[sub_i] = self.offset[orig_i]
            sub_matrices.append(sub_mat)

        return sub_matrices

    def decompose_into_capsules(self, name_prefix: str = "capsule") -> List['CompositeTensorDescriptor']:
        """
        Decomposes the coupling matrix into independent state tensor capsules (Rule 14.e).
        """
        blocks = self.decompose_block_diagonal()
        capsules = []
        for i, block in enumerate(blocks):
            name = f"{name_prefix}_{i}" if len(blocks) > 1 else name_prefix
            capsules.append(CompositeTensorDescriptor(
                name=name,
                channel_names=block.vars,
                internal_matrix=block,
                interface_dof=block.dim
            ))
        return capsules


# Alias for backward compatibility
RegisterCouplingMatrix = VariableCouplingMatrix


# ============================================================================
# 4.6. Abstract State Tensor Capsule & Storage Layout (Rule 14.e)
# ============================================================================

class StorageLayout:
    """
    Optional physical memory and binary layout descriptor for a state capsule (Rule 14.e).
    Maps abstract mathematical channels to concrete hardware/binary byte offsets,
    struct alignments, and memory strides.
    """
    def __init__(
        self,
        field_offsets: Optional[Dict[str, int]] = None,
        total_stride_bytes: int = 0,
        alignment: int = 4,
        base_register: Optional[str] = None
    ):
        self.field_offsets: Dict[str, int] = dict(field_offsets) if field_offsets else {}
        self.total_stride_bytes: int = total_stride_bytes
        self.alignment: int = alignment
        self.base_register: Optional[str] = base_register

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_offsets": dict(self.field_offsets),
            "total_stride_bytes": self.total_stride_bytes,
            "alignment": self.alignment,
            "base_register": self.base_register,
        }

    def __repr__(self) -> str:
        return (
            f"StorageLayout(stride={self.total_stride_bytes}B, align={self.alignment}, "
            f"offsets={self.field_offsets})"
        )


class CompositeTensorDescriptor:
    """
    Abstract State Tensor Capsule C = < D, X_vec, A_internal, D_interface, Offsets > (Rule 14.e).
    
    A domain-agnostic, multi-dimensional entity descriptor representing coupled state slots.
    Completely decoupled from physical machine bytes unless an optional `StorageLayout` is attached.
    """
    def __init__(
        self,
        name: str,
        channel_names: List[str],
        internal_matrix: Optional[VariableCouplingMatrix] = None,
        interface_dof: Optional[int] = None,
        storage_layout: Optional[StorageLayout] = None,
    ):
        self.name = name
        self.channel_names = list(channel_names)
        self.dim = len(self.channel_names)
        self.internal_matrix = internal_matrix or VariableCouplingMatrix(self.channel_names)
        self.interface_dof = interface_dof if interface_dof is not None else self.dim
        self.storage_layout = storage_layout

    @property
    def D(self) -> int:
        """Total internal dimension/rank."""
        return self.dim

    @property
    def D_interface(self) -> int:
        """External boundary interface rank."""
        return self.interface_dof

    def pow_mod(self, p: int, mod: int = 2**32) -> 'CompositeTensorDescriptor':
        """
        Advances this capsule across p iterations via fast O(log p) matrix exponentiation.
        """
        powered_mat = self.internal_matrix.pow_mod(p, mod=mod)
        return CompositeTensorDescriptor(
            name=f"{self.name}_pow_{p}",
            channel_names=self.channel_names,
            internal_matrix=powered_mat,
            interface_dof=self.interface_dof,
            storage_layout=self.storage_layout
        )

    def condense_to_interface(
        self,
        interface_vars: Optional[List[str]] = None
    ) -> 'CompositeTensorDescriptor':
        """
        Applies Static Condensation / Schur Reduction to project the capsule's internal
        state dynamics onto its boundary interface slots (Rule 14.b):
            X_all = [X_m; X_s]  where X_m is interface (Master), X_s is internal (Slave).
        Eliminates internal slave DOFs X_s and constructs the exact Back-Substitution
        reconstruction operator T_recovery so internal states can be queried in O(1):
            X_s(N) = T_recovery * X_m(N) + C_recovery
        Returns a condensed CompositeTensorDescriptor with dimension = len(interface_vars).
        """
        if interface_vars is None:
            if self.interface_dof >= self.dim:
                return self
            interface_vars = self.channel_names[:self.interface_dof]

        master_vars = [v for v in interface_vars if v in self.channel_names]
        slave_vars = [v for v in self.channel_names if v not in master_vars]

        if not slave_vars or not master_vars:
            return self

        dim_m = len(master_vars)
        dim_s = len(slave_vars)

        m_idx = [self.internal_matrix.var_to_idx[v] for v in master_vars]
        s_idx = [self.internal_matrix.var_to_idx[v] for v in slave_vars]

        mat = self.internal_matrix.matrix
        offset = self.internal_matrix.offset

        A_mm = [[mat[i][j] for j in m_idx] for i in m_idx]
        A_ms = [[mat[i][j] for j in s_idx] for i in m_idx]
        A_sm = [[mat[i][j] for j in m_idx] for i in s_idx]
        A_ss = [[mat[i][j] for j in s_idx] for i in s_idx]

        B_m = [offset[i] for i in m_idx]
        B_s = [offset[i] for i in s_idx]

        # Solve (I - A_ss) * T = A_sm and (I - A_ss) * C = B_s via exact rational Gaussian elimination
        M_s = [[(Fraction(1, 1) if i == j else Fraction(0, 1)) - _to_frac(A_ss[i][j]) for j in range(dim_s)] for i in range(dim_s)]
        aug_dim = dim_s + dim_m + 1
        aug = []
        for i in range(dim_s):
            row = list(M_s[i]) + [_to_frac(A_sm[i][j]) for j in range(dim_m)] + [_to_frac(B_s[i])]
            aug.append(row)

        is_singular = False
        for i in range(dim_s):
            pivot = i
            max_val = abs(aug[i][i])
            for k in range(i + 1, dim_s):
                if abs(aug[k][i]) > max_val:
                    max_val = abs(aug[k][i])
                    pivot = k
            if max_val == 0:
                is_singular = True
                break
            if pivot != i:
                aug[i], aug[pivot] = aug[pivot], aug[i]

            pivot_val = aug[i][i]
            for j in range(aug_dim):
                aug[i][j] /= pivot_val

            for k in range(dim_s):
                if k != i:
                    factor = aug[k][i]
                    for j in range(aug_dim):
                        aug[k][j] -= factor * aug[i][j]

        if is_singular:
            T = [[_to_frac(A_sm[i][j]) for j in range(dim_m)] for i in range(dim_s)]
            C = [_to_frac(B_s[i]) for i in range(dim_s)]
        else:
            T = [[aug[i][dim_s + j] for j in range(dim_m)] for i in range(dim_s)]
            C = [aug[i][dim_s + dim_m] for i in range(dim_s)]

        # A_cond = A_mm + A_ms * T
        A_cond = [[_to_frac(A_mm[i][j]) for j in range(dim_m)] for i in range(dim_m)]
        B_cond = [_to_frac(B_m[i]) for i in range(dim_m)]

        for i in range(dim_m):
            for j in range(dim_m):
                for s in range(dim_s):
                    A_cond[i][j] += _to_frac(A_ms[i][s]) * T[s][j]
            for s in range(dim_s):
                B_cond[i] += _to_frac(A_ms[i][s]) * C[s]

        condensed_matrix = VariableCouplingMatrix(master_vars)
        for i in range(dim_m):
            for j in range(dim_m):
                condensed_matrix.matrix[i][j] = _normalize_num(A_cond[i][j])
            condensed_matrix.offset[i] = _normalize_num(B_cond[i])

        recovery_map: Dict[str, AffineExpr] = {}
        for s in range(dim_s):
            s_name = slave_vars[s]
            coeffs = {}
            for j in range(dim_m):
                coeff = _normalize_num(T[s][j])
                if coeff != 0:
                    coeffs[master_vars[j]] = coeff
            c_val = _normalize_num(C[s])
            recovery_map[s_name] = AffineExpr(coeffs=coeffs, offset=c_val)

        cond_layout = None
        if self.storage_layout:
            cond_offsets = {k: v for k, v in self.storage_layout.field_offsets.items() if k in master_vars}
            cond_layout = StorageLayout(
                field_offsets=cond_offsets,
                total_stride_bytes=self.storage_layout.total_stride_bytes,
                alignment=self.storage_layout.alignment,
                base_register=self.storage_layout.base_register
            )

        condensed_capsule = CompositeTensorDescriptor(
            name=f"{self.name}_condensed",
            channel_names=master_vars,
            internal_matrix=condensed_matrix,
            interface_dof=dim_m,
            storage_layout=cond_layout
        )
        condensed_capsule.recovery_map = recovery_map
        return condensed_capsule

    def recover_internal_state(
        self,
        master_values: Dict[str, Union[int, float, Fraction]]
    ) -> Dict[str, Union[int, float, Fraction]]:
        """
        Recovers the exact values of all internal/condensed slave variables in O(1)
        via algebraic back-substitution (Rule 14.b):
            X_s = T_recovery * X_m + C_recovery
        """
        if not hasattr(self, 'recovery_map') or not self.recovery_map:
            return {}

        results = {}
        has_float = any(isinstance(v, float) for v in master_values.values())
        for s_name, expr in self.recovery_map.items():
            val = _to_frac(expr.offset)
            for m_name, coeff in expr.coeffs.items():
                m_val = master_values.get(m_name, 0)
                val += _to_frac(coeff) * _to_frac(m_val)
            norm = _normalize_num(val)
            if has_float and isinstance(norm, Fraction):
                results[s_name] = float(norm)
            else:
                results[s_name] = norm
        return results

    def to_dict(self) -> Dict[str, Any]:
        rec_dict = None
        if hasattr(self, 'recovery_map') and self.recovery_map:
            rec_dict = {k: {"coeffs": v.coeffs, "offset": v.offset} for k, v in self.recovery_map.items()}
        return {
            "name": self.name,
            "dim": self.dim,
            "channel_names": list(self.channel_names),
            "interface_dof": self.interface_dof,
            "internal_matrix": {
                "matrix": self.internal_matrix.matrix,
                "offset": self.internal_matrix.offset,
                "vars": self.internal_matrix.vars
            },
            "storage_layout": self.storage_layout.to_dict() if self.storage_layout else None,
            "recovery_map": rec_dict
        }

    def __repr__(self) -> str:
        storage_str = f", layout={self.storage_layout}" if self.storage_layout else ""
        cond_str = f", condensed={len(self.recovery_map)} vars" if getattr(self, 'recovery_map', None) else ""
        return (
            f"CompositeTensorDescriptor(name={self.name!r}, D={self.dim}, "
            f"D_int={self.interface_dof}, channels={self.channel_names}{storage_str}{cond_str})"
        )


# ============================================================================
# 4.7. Spatiotemporal Coordinates & 2D Tick Model (Rule 12)
# ============================================================================

class SpatiotemporalCoordinate:
    """
    Rule 12.a: 2D Space-Time Coordinate <k, xi>.
    Represents an exact execution instant where:
        - k: loop iteration index (0 <= k < N) or symbolic loop index string
        - xi: intra-loop instruction offset or execution phase (0 <= xi < mu)
    Provides O(1) lexicographical ordering for resolving read/write causality and RAW hazards.
    """
    def __init__(self, k: Union[int, str], xi: int = 0):
        self.k: Union[int, str] = k
        self.xi: int = int(xi)

    def is_concrete(self) -> bool:
        return isinstance(self.k, int)

    def compare(self, other: 'SpatiotemporalCoordinate') -> int:
        """
        Lexicographical comparison:
            Returns -1 if self < other, 0 if self == other, 1 if self > other.
        If symbolic strings cannot be resolved, compares purely on xi if k is identical.
        """
        if isinstance(self.k, int) and isinstance(other.k, int):
            if self.k < other.k:
                return -1
            elif self.k > other.k:
                return 1
            else:
                return -1 if self.xi < other.xi else (1 if self.xi > other.xi else 0)
        elif self.k == other.k:
            return -1 if self.xi < other.xi else (1 if self.xi > other.xi else 0)
        else:
            # Symbolic comparison fallback
            return -1 if str(self.k) < str(other.k) else (1 if str(self.k) > str(other.k) else 0)

    def __lt__(self, other: 'SpatiotemporalCoordinate') -> bool:
        return self.compare(other) < 0

    def __le__(self, other: 'SpatiotemporalCoordinate') -> bool:
        return self.compare(other) <= 0

    def __gt__(self, other: 'SpatiotemporalCoordinate') -> bool:
        return self.compare(other) > 0

    def __ge__(self, other: 'SpatiotemporalCoordinate') -> bool:
        return self.compare(other) >= 0

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, SpatiotemporalCoordinate):
            return self.k == other.k and self.xi == other.xi
        return False

    def __hash__(self) -> int:
        return hash((self.k, self.xi))

    def to_dict(self) -> Dict[str, Any]:
        return {"k": self.k, "xi": self.xi}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SpatiotemporalCoordinate':
        return cls(k=data["k"], xi=data.get("xi", 0))

    def __repr__(self) -> str:
        return f"<{self.k}, xi={self.xi}>"


class SpatiotemporalTickModel:
    """
    Rule 12: Unified Spatiotemporal 2D Tick Model.
    Governs instruction timestamps, memory provenance ordering, and epoch anchoring:
        Tick(k, xi) = T_0 + k * T_stride + xi + sum(Branch_j * Delta_xi_j)
        T_epoch = T_0 + N * T_stride
    """
    def __init__(
        self,
        T_0: int = 0,
        inter_stride: int = 1,
        intra_steps: int = 1,
        branch_penalties: Optional[Dict[str, int]] = None
    ):
        self.T_0: int = int(T_0)
        self.inter_stride: int = max(1, int(inter_stride))
        self.intra_steps: int = max(1, int(intra_steps))
        self.branch_penalties: Dict[str, int] = dict(branch_penalties or {})

    def eval_tick(
        self,
        k: Union[int, str],
        xi: int = 0,
        branch_mask: Optional[Dict[str, bool]] = None
    ) -> Union[int, str]:
        """
        Calculates the exact scalar tick for iteration k, intra-phase xi in O(1).
        """
        branch_delta = 0
        if branch_mask:
            for branch_name, is_taken in branch_mask.items():
                if is_taken and branch_name in self.branch_penalties:
                    branch_delta += self.branch_penalties[branch_name]

        if isinstance(k, int):
            return self.T_0 + (k * self.inter_stride) + xi + branch_delta
        else:
            terms = []
            if self.T_0 != 0:
                terms.append(str(self.T_0))
            if self.inter_stride == 1:
                terms.append(str(k))
            else:
                terms.append(f"{k} * {self.inter_stride}")
            total_intra = xi + branch_delta
            if total_intra != 0:
                terms.append(str(total_intra))
            return " + ".join(terms) if terms else "0"

    def eval_epoch(self, N: Union[int, str]) -> Union[int, str]:
        """
        Rule 12.d: Epoch Anchoring Rule.
        Computes the global exit timestamp T_epoch = T_0 + N * inter_stride in O(1).
        """
        if isinstance(N, int):
            return self.T_0 + (N * self.inter_stride)
        else:
            stride_str = f"{N} * {self.inter_stride}" if self.inter_stride != 1 else str(N)
            return f"{self.T_0} + {stride_str}" if self.T_0 != 0 else stride_str

    def eval_state_at(
        self,
        k: int,
        xi: int,
        initial_state: Dict[str, float],
        capsule: Optional['CompositeTensorDescriptor'] = None,
        intra_matrix: Optional[VariableCouplingMatrix] = None
    ) -> Dict[str, float]:
        """
        Rule 12.b: Continuous Space-Time State Evolution Equation:
            State(k, xi) = A_intra(xi) * (A_inter^k * S_0) + C(k, xi)
        Advances the state across k full iterations and applies intra-iteration step xi.
        """
        current_state = dict(initial_state)

        # 1. Advance through k inter-iteration cycles via binary matrix exponentiation
        if capsule is not None and k > 0:
            pow_mat = capsule.internal_matrix.pow_mod(k)
            next_state = {}
            for i, var in enumerate(pow_mat.vars):
                val = float(pow_mat.offset[i])
                for j, src_var in enumerate(pow_mat.vars):
                    val += pow_mat.matrix[i][j] * float(current_state.get(src_var, 0.0))
                next_state[var] = val
            current_state.update(next_state)

        # 2. Advance through xi intra-iteration micro-steps
        if intra_matrix is not None and xi > 0:
            pow_intra = intra_matrix.pow_mod(xi)
            next_state = {}
            for i, var in enumerate(pow_intra.vars):
                val = float(pow_intra.offset[i])
                for j, src_var in enumerate(pow_intra.vars):
                    val += pow_intra.matrix[i][j] * float(current_state.get(src_var, 0.0))
                next_state[var] = val
            current_state.update(next_state)

        return current_state

    def is_write_before_read(
        self,
        write_coord: SpatiotemporalCoordinate,
        read_coord: SpatiotemporalCoordinate
    ) -> bool:
        """
        Rule 12.c: Resolves Read-After-Write (RAW) data hazards in O(1) via lexicographical ordering.
        """
        return write_coord < read_coord

    def to_dict(self) -> Dict[str, Any]:
        return {
            "T_0": self.T_0,
            "inter_stride": self.inter_stride,
            "intra_steps": self.intra_steps,
            "branch_penalties": dict(self.branch_penalties)
        }

    def __repr__(self) -> str:
        return (
            f"SpatiotemporalTickModel(T_0={self.T_0}, stride={self.inter_stride}, "
            f"intra_steps={self.intra_steps})"
        )


# ============================================================================
# 4.8. Orbit-Perturbation Separation & Telescoping Turn Counter (Rule 13)
# ============================================================================

class OrbitCarrierDescriptor:
    """
    Rule 13.a: Orbit Carrier Descriptor (S_carrier).
    Represents the primary predictable, unperturbed baseline trajectory:
        - Matrix recurrence: A_carrier^k * S_0 + B_carrier(k)
        - Harmonic / Rotational carrier: x(t) = R * cos(omega * t), y(t) = R * sin(omega * t)
        - Uniform linear drift: x(t) = x_0 + v * t
    Evaluates in O(1) or O(log k) without iteration.
    """
    def __init__(
        self,
        name: str = "carrier",
        carrier_matrix: Optional[VariableCouplingMatrix] = None,
        angular_frequency: Optional[float] = None,
        harmonic_pairs: Optional[List[Tuple[str, str]]] = None,
        eccentricity: float = 0.0,
    ):
        self.name = name
        self.carrier_matrix = carrier_matrix
        self.angular_frequency = angular_frequency
        self.harmonic_pairs = list(harmonic_pairs or [])
        self.eccentricity = float(eccentricity)

    def eval_carrier(
        self,
        k: int,
        initial_state: Dict[str, float]
    ) -> Dict[str, float]:
        """
        Advances the unperturbed carrier state across k iterations in O(1) / O(log k).
        """
        state = dict(initial_state)
        if k <= 0:
            return state

        # 1. Harmonic / Symplectic rotational carrier if configured
        if self.angular_frequency is not None and self.harmonic_pairs:
            import math
            theta = self.angular_frequency * k
            cos_t = math.cos(theta)
            sin_t = math.sin(theta)
            r_scale = (1.0 - self.eccentricity * cos_t) if self.eccentricity else 1.0
            for x_var, y_var in self.harmonic_pairs:
                x0 = float(state.get(x_var, 0.0))
                y0 = float(state.get(y_var, 0.0))
                state[x_var] = (x0 * cos_t - y0 * sin_t) * r_scale
                state[y_var] = (x0 * sin_t + y0 * cos_t) * r_scale

        # 2. General linear affine recurrence matrix if present
        if self.carrier_matrix is not None:
            pow_mat = self.carrier_matrix.pow_mod(k)
            for i, var in enumerate(pow_mat.vars):
                val = float(pow_mat.offset[i])
                for j, src_var in enumerate(pow_mat.vars):
                    val += pow_mat.matrix[i][j] * float(initial_state.get(src_var, 0.0))
                state[var] = val

        return state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "carrier_matrix": {
                "vars": self.carrier_matrix.vars,
                "matrix": self.carrier_matrix.matrix,
                "offset": self.carrier_matrix.offset,
            } if self.carrier_matrix else None,
            "angular_frequency": self.angular_frequency,
            "harmonic_pairs": self.harmonic_pairs,
            "eccentricity": self.eccentricity,
        }

    def __repr__(self) -> str:
        return f"OrbitCarrierDescriptor(name={self.name!r}, omega={self.angular_frequency})"


class PerturbationEpochModel:
    """
    Rule 13.b & 13.c: Telescoping Perturbation Epoch Model & Turn Counter (K_flip).
    Governs discrete event thresholds, collision bounces, and episodic impulses:
        K_epoch(k) = floor((k - k_start) / epoch_stride)
        Sign_flip(k) = (-1)^K_epoch * restitution^K_epoch
        Delta_S(k) = K_epoch * J_impulse + K_epoch * J_secular
    """
    def __init__(
        self,
        epoch_stride: int = 1,
        k_start: int = 0,
        restitution_coeff: float = 1.0,
        reversal_vars: Optional[List[str]] = None,
        impulse_vector: Optional[Dict[str, float]] = None,
        secular_drift: Optional[Dict[str, float]] = None,
    ):
        self.epoch_stride: int = max(1, int(epoch_stride))
        self.k_start: int = int(k_start)
        self.restitution_coeff: float = float(restitution_coeff)
        self.reversal_vars: List[str] = list(reversal_vars or [])
        self.impulse_vector: Dict[str, float] = dict(impulse_vector or {})
        self.secular_drift: Dict[str, float] = dict(secular_drift or {})

    def eval_epoch_index(self, k: int) -> int:
        """
        Calculates the active epoch count / number of turn events in O(1).
        """
        if k < self.k_start:
            return 0
        return (k - self.k_start) // self.epoch_stride

    def eval_sign_multiplier(self, k: int, var: str) -> float:
        """
        Calculates the velocity sign flip (-1)^K * e^K for bouncing/reversing variables.
        """
        if var not in self.reversal_vars:
            return 1.0
        n_epochs = self.eval_epoch_index(k)
        if n_epochs == 0:
            return 1.0
        sign = -1.0 if (n_epochs % 2 == 1) else 1.0
        damping = (self.restitution_coeff ** n_epochs) if self.restitution_coeff != 1.0 else 1.0
        return sign * damping

    def eval_accumulated_impulse(self, k: int) -> Dict[str, float]:
        """
        Accumulates discrete episodic impulses and secular drifts in O(1).
        """
        n_epochs = self.eval_epoch_index(k)
        if n_epochs == 0:
            return {}
        result = {}
        # 1. Discrete pulse impulses (J_e)
        for var, val in self.impulse_vector.items():
            result[var] = result.get(var, 0.0) + (n_epochs * val)
        # 2. Secular drift (continuous long-term accumulation)
        for var, val in self.secular_drift.items():
            result[var] = result.get(var, 0.0) + (n_epochs * val)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch_stride": self.epoch_stride,
            "k_start": self.k_start,
            "restitution_coeff": self.restitution_coeff,
            "reversal_vars": self.reversal_vars,
            "impulse_vector": self.impulse_vector,
            "secular_drift": self.secular_drift,
        }

    def __repr__(self) -> str:
        return (
            f"PerturbationEpochModel(stride={self.epoch_stride}, "
            f"reversal={self.reversal_vars}, e={self.restitution_coeff})"
        )


class OrbitPerturbationSystem:
    """
    Rule 13: Unified Orbit-Perturbation Separation System.
    Combines the baseline unperturbed carrier with episodic perturbation pulses:
        S(k) = S_carrier(k) + Delta_S_perturbation(k)
    Enables instant closed-form jumps across millions of simulation cycles in O(1).
    """
    def __init__(
        self,
        carrier: OrbitCarrierDescriptor,
        perturbation: Optional[PerturbationEpochModel] = None,
        target_collection: Optional[str] = None,
        body_perturbations: Optional[Dict[int, PerturbationEpochModel]] = None,
        neighbor_cascade_matrix: Optional[List[Tuple[int, int, float]]] = None,
    ):
        self.carrier = carrier
        self.perturbation = perturbation or PerturbationEpochModel()
        self.target_collection = target_collection
        self.body_perturbations: Dict[int, PerturbationEpochModel] = dict(body_perturbations or {})
        self.neighbor_cascade_matrix: List[Tuple[int, int, float]] = list(neighbor_cascade_matrix or [])

    def eval_total_state(
        self,
        k: int,
        initial_state: Dict[str, float]
    ) -> Dict[str, float]:
        """
        Evaluates the combined single-body orbit + perturbation state at step k in O(1).
        """
        # 1. Advance along primary carrier trajectory S_carrier(k)
        state = self.carrier.eval_carrier(k, initial_state)

        # 2. Apply sign reversals and restitution damping
        for var in self.perturbation.reversal_vars:
            if var in state:
                mult = self.perturbation.eval_sign_multiplier(k, var)
                state[var] = state[var] * mult

        # 3. Add accumulated discrete impulses and secular drifts
        impulses = self.perturbation.eval_accumulated_impulse(k)
        for var, delta in impulses.items():
            state[var] = state.get(var, 0.0) + delta

        return state

    def eval_multi_body_state(
        self,
        k: int,
        initial_bodies: list,
        dt: float = 0.01
    ) -> list:
        """
        Evaluates the entire multi-body collection state at step k in O(1).
        Applies carrier harmonic rotations, per-body perturbation epochs, and
        the coupled neighbor cascade transmission down the planetary chain.
        """
        import copy
        import math
        bodies = copy.deepcopy(initial_bodies)
        if len(bodies) <= 1 or k <= 0:
            return bodies

        # Dynamically discover dominant central attractor (body with largest mass in collection)
        central_idx = max(range(len(bodies)), key=lambda i: bodies[i][2] if len(bodies[i]) > 2 else 0.0)
        central_mass = bodies[central_idx][2] if len(bodies[central_idx]) > 2 else 1.0
        central_pos = bodies[central_idx][0]
        dt_factor = dt

        n_orbiters = len(bodies)
        dr_x = [0.0] * n_orbiters
        dr_y = [0.0] * n_orbiters
        dv_x = [0.0] * n_orbiters
        dv_y = [0.0] * n_orbiters

        # 1. Keplerian harmonic carrier rotation for all orbiting bodies around the central attractor
        orbiters_info = []
        for idx in range(n_orbiters):
            if idx == central_idx:
                continue
            r = bodies[idx][0]
            v = bodies[idx][1]
            rel_x = r[0] - central_pos[0]
            rel_y = r[1] - central_pos[1]
            rel_z = r[2] - central_pos[2]
            r0 = math.sqrt(rel_x * rel_x + rel_y * rel_y + rel_z * rel_z)
            if r0 < 1e-12:
                continue

            b_mass = bodies[idx][2] if len(bodies[idx]) > 2 else 0.001
            omega = math.sqrt(central_mass / (r0 ** 3)) * dt_factor
            orbiters_info.append({"idx": idx, "r": r0, "mass": b_mass, "omega": omega})

            sl_sign = 1.0 if (rel_x * v[1] - rel_y * v[0]) >= 0 else -1.0
            theta = sl_sign * abs(omega) * k
            cos_t = math.cos(theta)
            sin_t = math.sin(theta)

            # Rotate positions around central attractor
            nx = rel_x * cos_t - rel_y * sin_t
            ny = rel_x * sin_t + rel_y * cos_t
            r[0] = central_pos[0] + nx
            r[1] = central_pos[1] + ny

            # Rotate velocities
            nvx = v[0] * cos_t - v[1] * sin_t
            nvy = v[0] * sin_t + v[1] * cos_t
            v[0] = nvx
            v[1] = nvy

        # 2. Accumulate episodic impulses and synodic perturbation models
        if self.body_perturbations:
            for idx, p_model in self.body_perturbations.items():
                if idx < n_orbiters:
                    impulses = p_model.eval_accumulated_impulse(k)
                    dr_x[idx] = impulses.get("x", 0.0)
                    dr_y[idx] = impulses.get("y", 0.0)
                    dv_x[idx] = impulses.get("vx", 0.0)
                    dv_y[idx] = impulses.get("vy", 0.0)
        elif len(orbiters_info) > 1:
            # Dynamically compute mutual synodic impulses from primary perturber
            for i_info in orbiters_info:
                idx_i = i_info["idx"]
                r_i = i_info["r"]
                omega_i = i_info["omega"]

                # Find dominant perturber j for body i
                best_j = None
                max_force = -1.0
                for j_info in orbiters_info:
                    if j_info["idx"] == idx_i:
                        continue
                    dist_ij = max(0.1, abs(r_i - j_info["r"]))
                    force_ij = j_info["mass"] / (dist_ij ** 2)
                    if force_ij > max_force:
                        max_force = force_ij
                        best_j = j_info

                if best_j:
                    delta_omega = abs(omega_i - best_j["omega"])
                    t_synodic = max(10, int(abs(2 * math.pi / delta_omega))) if delta_omega > 1e-9 else 1000
                    dist_ij = max(0.1, abs(r_i - best_j["r"]))
                    impulse_mag = (best_j["mass"] * dt) / (dist_ij ** 2)
                    sign = -1.0 if r_i < best_j["r"] else 1.0

                    k_epochs = max(0, k // t_synodic)
                    dr_x[idx_i] += k_epochs * sign * impulse_mag * dt * 0.05
                    dv_x[idx_i] += k_epochs * sign * impulse_mag * 0.1

        # 3. Propagate coupled neighbor cascade transmission
        if self.neighbor_cascade_matrix:
            for src_idx, tgt_idx, ratio in self.neighbor_cascade_matrix:
                if src_idx < n_orbiters and tgt_idx < n_orbiters:
                    dr_x[tgt_idx] += ratio * dr_x[src_idx]
                    dr_y[tgt_idx] += ratio * dr_y[src_idx]
                    dv_x[tgt_idx] += ratio * dv_x[src_idx]
                    dv_y[tgt_idx] += ratio * dv_y[src_idx]

        # 4. Apply final displacements
        for idx in range(n_orbiters):
            if idx == central_idx:
                continue
            bodies[idx][0][0] += dr_x[idx]
            bodies[idx][0][1] += dr_y[idx]
            bodies[idx][1][0] += dv_x[idx]
            bodies[idx][1][1] += dv_y[idx]

        return bodies

    def to_dict(self) -> Dict[str, Any]:
        return {
            "carrier": self.carrier.to_dict(),
            "perturbation": self.perturbation.to_dict(),
            "target_collection": self.target_collection,
            "body_perturbations": {
                idx: p.to_dict() for idx, p in self.body_perturbations.items()
            },
            "neighbor_cascade_matrix": self.neighbor_cascade_matrix,
        }

    def __repr__(self) -> str:
        return (
            f"OrbitPerturbationSystem(carrier={self.carrier!r}, "
            f"perturb={self.perturbation!r}, "
            f"target={self.target_collection!r}, "
            f"bodies_count={len(self.body_perturbations)}, "
            f"cascade_links={len(self.neighbor_cascade_matrix)})"
        )


# ============================================================================
# 4.5. Array & Table Descriptors (Rule 8.e)
# ============================================================================

class ArrayDescriptor:
    """
    Mathematical descriptor for a memory or source-level array/table (Rule 8.e).
    Represents the array's bounds as a StridedInterval:
        I_bounds = 1[0, length - 1]
    Enables O(1) index-bounds intersection, out-of-bounds pruning, and cycle sum lifting.
    """
    def __init__(
        self,
        name: str,
        length: int,
        elements: Optional[List[Any]] = None,
        bit_width: int = 64
    ):
        from strilight.engine.domains import StridedInterval
        self.name = name
        self.length = max(0, int(length))
        self.elements = list(elements) if elements is not None else None
        self.bit_width = bit_width

        # Invariant: I_bounds = 1[0, length - 1]
        max_idx = max(0, self.length - 1) if self.length > 0 else 0
        self.bounds_interval = StridedInterval(
            0,
            max_idx,
            bit_width=self.bit_width,
            stride=1
        )

        # Precompute cycle sum if elements are numeric
        self.cycle_sum: Optional[int] = None
        if self.elements is not None and len(self.elements) > 0 and all(isinstance(x, (int, float)) for x in self.elements):
            self.cycle_sum = int(sum(self.elements))

    def intersect_index(self, index_interval: Any) -> Any:
        """
        Intersects an index StridedInterval with the array bounds in O(1).
        Logs a warning if the index range is completely outside the array bounds.
        """
        if self.length == 0:
            logger.warning(
                "[ArrayDescriptor] Attempted to index zero-length array '%s'!",
                self.name
            )
            return self.bounds_interval

        valid_interval = index_interval.intersect(self.bounds_interval)
        is_empty = (
            (valid_interval.min_val == 0 and valid_interval.max_val == 0 and self.bounds_interval.max_val > 0)
            or (valid_interval.min_val > valid_interval.max_val)
        )

        if is_empty or index_interval.min_val >= self.length or index_interval.max_val < 0:
            logger.warning(
                "[ArrayDescriptor] Index range [0x%X, 0x%X] for array '%s' is completely OUT OF BOUNDS [0, %d]! Dead path detected.",
                index_interval.min_val, index_interval.max_val, self.name, self.length - 1
            )
        return valid_interval

    def is_in_bounds(self, index_interval: Any) -> bool:
        """
        Returns True if the index interval is guaranteed to fall 100% within the array bounds.
        """
        if self.length == 0:
            return False
        return (index_interval.min_val >= 0 and index_interval.max_val < self.length)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "length": self.length,
            "bounds": [self.bounds_interval.min_val, self.bounds_interval.max_val],
            "stride": self.bounds_interval.stride,
            "cycle_sum": self.cycle_sum,
            "element_count": len(self.elements) if self.elements else 0
        }

    def __repr__(self) -> str:
        return f"<ArrayDescriptor name='{self.name}' len={self.length} bounds=[0, {self.bounds_interval.max_val}]>"


class ArraySliceMutation:
    """
    Mathematical representation of an in-place spatial array slice update (Rule 8.f).
    Tracks the target array, mutated index interval [0, N-1], and the value generation formula:
        kind: 'constant'   -> value = const
        kind: 'affine'     -> value(i) = base + i * stride
        kind: 'accumulate' -> value(i) = original[i] + delta
    """
    def __init__(
        self,
        target_array: str,
        slice_length: Optional[Union[int, str]] = None,
        kind: str = "constant",
        base: int = 0,
        stride: int = 0,
        constant_val: Optional[Any] = None,
        delta: Optional[int] = None
    ):
        self.target_array = target_array
        self.slice_length = slice_length
        self.kind = kind
        self.base = base
        self.stride = stride
        self.constant_val = constant_val
        self.delta = delta

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_array,
            "length": self.slice_length,
            "kind": self.kind,
            "base": self.base,
            "stride": self.stride,
            "constant_val": self.constant_val,
            "delta": self.delta,
        }

    def __repr__(self) -> str:
        return f"<ArraySliceMutation target='{self.target_array}' kind='{self.kind}' base={self.base} stride={self.stride}>"


# ============================================================================
# 5. AutoSyncDict & Loop Summary
# ============================================================================

class AutoSyncDict(dict):
    """
    Dictionary subclass that triggers a synchronization callback on item assignment or deletion,
    ensuring that mutations like `summary.deltas[reg] = delta` automatically synchronize
    with `summary.register_exprs`.
    """
    def __init__(self, on_change_callback: Optional[Callable[[str, Any], None]] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_change_callback = on_change_callback

    def __setitem__(self, key: str, value: Any):
        super().__setitem__(key, value)
        if self.on_change_callback:
            self.on_change_callback(key, value)

    def __delitem__(self, key: str):
        super().__delitem__(key)
        if self.on_change_callback:
            self.on_change_callback(key, None)

    def update(self, *args, **kwargs):
        other = dict(*args, **kwargs)
        for k, v in other.items():
            self[k] = v

    def pop(self, key, *args):
        res = super().pop(key, *args)
        if self.on_change_callback:
            self.on_change_callback(key, None)
        return res

    def clear(self):
        keys = list(self.keys())
        super().clear()
        if self.on_change_callback:
            for k in keys:
                self.on_change_callback(k, None)


class LoopExitGuard:
    """
    Formal mathematical representation of a Loop Exit Guard condition:
        LHS(N) <OP> RHS(N)
    """
    def __init__(
        self,
        lhs: Any,
        rhs: Any,
        jcc: str,
        is_exit_on_true: bool = True,
        slice_records: Optional[List[Any]] = None,
        exit_jmp: Optional[Any] = None,
    ):
        self.lhs = lhs
        self.rhs = rhs
        self.jcc = (jcc or "").lower().strip()
        self.is_exit_on_true = is_exit_on_true
        self.slice_records = slice_records or []
        self.exit_jmp = exit_jmp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lhs": self.lhs,
            "rhs": self.rhs,
            "jcc": self.jcc,
            "is_exit_on_true": self.is_exit_on_true,
        }


class LoopSummary:
    """
    Symbolic mathematical summary of a loop's effect.
    This is passed to the BackwardTracker (or Translator) to instantly jump over the loop.
    Unified with Universal Expression Tree AST (register_exprs).
    """
    def __init__(self):
        # Universal Symbolic AST Expressions for any variable/register/memory target
        self.var_exprs: Dict[str, VariableLoopExpr] = {}

        # Auto-syncing dictionaries for 100% full backward compatibility
        self.deltas: Dict[str, int] = AutoSyncDict(self._sync_delta)
        self.patterns: Dict[str, List[int]] = AutoSyncDict(self._sync_pattern)
        self.pattern_scales: Dict[str, str] = AutoSyncDict(self._sync_pattern_scale)
        self.constant_sets: Dict[str, int] = AutoSyncDict(self._sync_constant)
        self.geometric_shifts: Dict[str, Dict[str, Any]] = AutoSyncDict(self._sync_geometric)
        self.telescoping_cascades: Dict[str, TelescopingCascade] = AutoSyncDict(self._sync_telescoping)
        self.array_descriptors: Dict[str, ArrayDescriptor] = {}
        self.array_mutations: Dict[str, ArraySliceMutation] = {}
        self.has_unsupported_ops: bool = False

        self.coupling_matrix: Optional[VariableCouplingMatrix] = None
        self.capsules: List[CompositeTensorDescriptor] = []
        self.tick_model: Optional[SpatiotemporalTickModel] = None
        self.orbit_system: Optional[OrbitPerturbationSystem] = None
        self.target_collection: Optional[str] = None
        self.contract: Optional[Any] = None
        self.exit_condition: Optional[str] = None
        self.exit_records: List['TraceRecord'] = []
        self.exit_guard: Optional[LoopExitGuard] = None
        self.iterations: Optional[int] = None
        self.symbolic_iterations: Optional[str] = None
        self.inner_summaries: List['LoopSummary'] = []
        self.direct_deltas: Dict[str, int] = {}
        self.direct_patterns: Dict[str, List[int]] = {}
        self.direct_constant_sets: Dict[str, int] = {}
        self.direct_records: List['TraceRecord'] = []
        self.tick: Optional[int] = None

    def get_tick(self, k: Union[int, str], xi: int = 0) -> Union[int, str]:
        """Returns the scalar or symbolic execution tick at iteration k, intra-phase xi in O(1)."""
        if self.tick_model:
            return self.tick_model.eval_tick(k, xi)
        stride = 1
        if isinstance(k, int):
            return (self.tick or 0) + (k * stride) + xi
        return f"{self.tick or 0} + ({k} * {stride}) + {xi}"

    def get_epoch_tick(self) -> Union[int, str]:
        """Returns the exit epoch timestamp T_epoch in O(1)."""
        if self.tick_model:
            return self.tick_model.eval_epoch(self.iterations or self.symbolic_iterations or "N")
        n = self.iterations or self.symbolic_iterations or "N"
        if isinstance(n, int):
            return (self.tick or 0) + n
        return f"{self.tick or 0} + {n}"

    def eval_orbit_state(self, k: int, initial_state: Dict[str, float]) -> Dict[str, float]:
        """Evaluates total orbit + perturbation state at cycle k in O(1)."""
        if self.orbit_system:
            return self.orbit_system.eval_total_state(k, initial_state)
        return dict(initial_state)

    def perform_spatial_condensation_pass(self):
        """
        Executes Phase 1 Spatial Condensation Pass (Rule 14.d).
        Decomposes coupling_matrix into independent block-diagonal capsules,
        and condenses composite entities with interface_dof < dim.
        """
        if self.coupling_matrix and not self.coupling_matrix.is_identity():
            raw_capsules = self.coupling_matrix.decompose_into_capsules()
            condensed_capsules = []
            for cap in raw_capsules:
                if cap.interface_dof < cap.dim:
                    condensed_capsules.append(cap.condense_to_interface())
                else:
                    condensed_capsules.append(cap)
            self.capsules = condensed_capsules

    @property
    def register_exprs(self) -> Dict[str, VariableLoopExpr]:
        return self.var_exprs

    @register_exprs.setter
    def register_exprs(self, val: Dict[str, VariableLoopExpr]):
        self.var_exprs = val

    def _sync_delta(self, key: str, val: Optional[int]):
        if key not in self.var_exprs:
            self.var_exprs[key] = VariableLoopExpr(key)
        self.var_exprs[key].terms = [t for t in self.var_exprs[key].terms if not isinstance(t, LinearTerm)]
        if val is not None:
            self.var_exprs[key].add_term(LinearTerm(val))
        elif len(self.var_exprs[key].terms) == 0 and self.var_exprs[key].constant_val is None:
            self.var_exprs.pop(key, None)

    def _sync_pattern(self, key: str, val: Optional[List[int]]):
        if key not in self.var_exprs:
            self.var_exprs[key] = VariableLoopExpr(key)
        self.var_exprs[key].terms = [t for t in self.var_exprs[key].terms if not isinstance(t, PeriodicTerm)]
        if val is not None:
            scale_var = self.pattern_scales.get(key)
            self.var_exprs[key].add_term(PeriodicTerm(val, scale_var=scale_var))
        elif len(self.var_exprs[key].terms) == 0 and self.var_exprs[key].constant_val is None:
            self.var_exprs.pop(key, None)

    def _sync_pattern_scale(self, key: str, val: Optional[str]):
        if key in self.var_exprs:
            for t in self.var_exprs[key].terms:
                if isinstance(t, PeriodicTerm):
                    t.scale_var = val

    def _sync_constant(self, key: str, val: Optional[int]):
        if key not in self.var_exprs:
            self.var_exprs[key] = VariableLoopExpr(key)
        if val is not None:
            self.var_exprs[key].set_constant(val)
        else:
            self.var_exprs[key].constant_val = None
            if len(self.var_exprs[key].terms) == 0:
                self.var_exprs.pop(key, None)

    def _sync_geometric(self, key: str, val: Optional[Dict[str, Any]]):
        if key not in self.var_exprs:
            self.var_exprs[key] = VariableLoopExpr(key)
        self.var_exprs[key].terms = [t for t in self.var_exprs[key].terms if not isinstance(t, GeometricTerm)]
        if val is not None:
            self.var_exprs[key].add_term(GeometricTerm(
                base=val.get('base', 2),
                var=val.get('var'),
                val=val.get('val', 1),
                modulo_bits=val.get('modulo_bits', 0)
            ))
        elif len(self.var_exprs[key].terms) == 0 and self.var_exprs[key].constant_val is None:
            self.var_exprs.pop(key, None)

    def _sync_telescoping(self, key: str, val: Optional[TelescopingCascade]):
        if key not in self.var_exprs:
            self.var_exprs[key] = VariableLoopExpr(key)
        self.var_exprs[key].terms = [t for t in self.var_exprs[key].terms if not isinstance(t, TelescopingTerm)]
        if val is not None:
            self.var_exprs[key].add_term(TelescopingTerm(val, target_reg=key))
        elif len(self.var_exprs[key].terms) == 0 and self.var_exprs[key].constant_val is None:
            self.var_exprs.pop(key, None)

    @property
    def invariant_contract(self) -> 'LoopInvariantContract':
        """Returns the formal mathematical invariant contract for this loop."""
        return LoopInvariantContract(self)

    def get_invariant_contract(self) -> 'LoopInvariantContract':
        """Helper to retrieve the formal mathematical invariant contract."""
        return LoopInvariantContract(self)

    def to_python_code(self, func_name: str = "accelerated_loop", N_var: str = "N", preserve_names: bool = True) -> str:
        """Emits a complete, formatted Python function string in O(1)."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_python_code(self, func_name=func_name, N_var=N_var, preserve_names=preserve_names)

    def to_python_callable(self, func_name: str = "accelerated_loop", N_var: str = "N", preserve_names: bool = True) -> Callable:
        """Compiles the O(1) closed-form Python function into an executable callable."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_python_callable(self, func_name=func_name, N_var=N_var, preserve_names=preserve_names)

    def to_c_code(self, func_name: str = "accelerated_loop", N_var: str = "N", preserve_names: bool = True) -> str:
        """Emits a clean, typed C function string in O(1)."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_c_code(self, func_name=func_name, N_var=N_var, preserve_names=preserve_names)

    def to_python_statements(self, N_var: str = "N", in_place: bool = True) -> str:
        """Emits clean in-place Python statements (e.g. `acc += N // 4 * 105`)."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_python_statements(self, N_var=N_var, in_place=in_place)

    def to_c_statements(self, N_var: str = "N", in_place: bool = True) -> str:
        """Emits clean in-place C statements (e.g. `acc += (N / 4) * 105;`)."""
        from strilight.frontend.codegen import CodeGenerator
        return CodeGenerator.to_c_statements(self, N_var=N_var, in_place=in_place)

    def resolve_indirect_jump_targets(
        self,
        jump_reg: str,
        text_start: int,
        text_end: int,
        code_alignment: int = 16,
        initial_val: Optional[int] = None,
        bit_width: int = 64
    ) -> Any:
        """
        Intersects the loop equation bounds of jump_reg with the executable text section
        to compute the exact feasible indirect jump targets in O(1).

        Logs warning-level diagnostics when intersection is empty (dead path / crash)
        or when anomalous behavior is detected (misaligned stride, invalid bounds, etc.).
        """
        from strilight.engine.domains import StridedInterval

        if text_start >= text_end or text_start <= 0:
            logger.warning(
                "[Indirect Jump Resolution] Unusual or invalid text section bounds: [0x%X, 0x%X].",
                text_start, text_end
            )

        text_interval = StridedInterval(
            text_start,
            text_end,
            bit_width=bit_width,
            stride=code_alignment
        )

        reg_expr = self.var_exprs.get(jump_reg)
        base_val = initial_val if initial_val is not None else 0

        if reg_expr is None and jump_reg not in self.deltas and jump_reg not in self.constant_sets:
            logger.warning(
                "[Indirect Jump Resolution] Jump register '%s' has no loop induction formula in LoopSummary! "
                "Defaulting to unconstrained section bounds.",
                jump_reg
            )
            return text_interval

        if reg_expr and reg_expr.constant_val is not None:
            c = reg_expr.constant_val
            jump_interval = StridedInterval(c, c, bit_width=bit_width, stride=0)
        elif jump_reg in self.constant_sets:
            c = self.constant_sets[jump_reg]
            jump_interval = StridedInterval(c, c, bit_width=bit_width, stride=0)
        else:
            stride = 0
            if reg_expr:
                stride = reg_expr.get_scalar_stride() or 0
            if stride == 0 and jump_reg in self.deltas:
                stride = self.deltas[jump_reg]

            N = self.iterations if self.iterations > 0 else 1
            if stride >= 0:
                min_v = base_val
                max_v = base_val + (N * stride)
            else:
                min_v = base_val + (N * stride)
                max_v = base_val

            s = abs(stride) if stride != 0 else 0
            jump_interval = StridedInterval(min_v, max_v, bit_width=bit_width, stride=s)

        feasible_targets = jump_interval.intersect(text_interval)

        is_empty = (feasible_targets.min_val == 0 and feasible_targets.max_val == 0) or (feasible_targets.min_val > feasible_targets.max_val)
        if is_empty:
            logger.warning(
                "[Indirect Jump Resolution] Jump register '%s' produced ZERO feasible targets in text section [0x%X, 0x%X]! "
                "Dead path or invalid jump target detected: jump_interval=[0x%X, 0x%X] Stride=%d.",
                jump_reg, text_start, text_end, jump_interval.min_val, jump_interval.max_val, jump_interval.stride
            )
        else:
            if feasible_targets.stride == 1 and code_alignment > 1:
                logger.warning(
                    "[Indirect Jump Resolution] Feasible targets for '%s' lost alignment constraint: "
                    "stride collapsed to 1 (expected multiple of %d). Targets=[0x%X, 0x%X].",
                    jump_reg, code_alignment, feasible_targets.min_val, feasible_targets.max_val
                )
            if feasible_targets.min_val == feasible_targets.max_val:
                logger.info(
                    "[Indirect Jump Resolution] Indirect jump on '%s' successfully devirtualized to exact single target 0x%X.",
                    jump_reg, feasible_targets.min_val
                )

        return feasible_targets



class LoopInvariantContract:
    """
    Explicit mathematical contract for loop invariants and exact termination boundaries.
    Provides closed-form induction formulas for both iteration N and iteration N-1 (the Iron Constraint).
    """
    def __init__(self, summary: LoopSummary):
        self.summary = summary

    def get_induction_formulas(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns the closed-form transition equations for each induction variable:
        The Grand Master Recurrence:
            State(N) = A(N) * State_0 + Delta_total(N)
        """
        formulas = {}
        if getattr(self.summary, 'register_exprs', None):
            for var, expr in self.summary.register_exprs.items():
                formulas[var] = expr.to_induction_formula()

        # Fallback for legacy dict properties if any are set outside register_exprs
        for var, delta in getattr(self.summary, 'deltas', {}).items():
            if var not in formulas:
                formulas[var] = {
                    "type": "linear",
                    "delta": delta,
                    "stride": delta,
                    "formula_at_N": f"{var}_0 + ({delta}) * N",
                    "formula_at_N_minus_1": f"{var}_0 + ({delta}) * (N - 1)"
                }
        for var, cascade in getattr(self.summary, 'telescoping_cascades', {}).items():
            if var not in formulas:
                t_formula = cascade.get_telescoping_formula()
                formulas[var] = {
                    "type": "telescoping",
                    "telescoping_cascade": cascade.to_dict(),
                    "formula_at_N": f"{var}_0 + ({t_formula}) * N",
                    "formula_at_N_minus_1": f"{var}_0 + ({t_formula}) * (N - 1)"
                }
        for var, pattern in getattr(self.summary, 'patterns', {}).items():
            if var not in formulas:
                p_len = len(pattern)
                p_sum = sum(pattern)
                formulas[var] = {
                    "type": "periodic",
                    "pattern": pattern,
                    "period": p_len,
                    "cycle_sum": p_sum,
                    "formula_at_N": f"{var}_0 + (N // {p_len}) * {p_sum} + prefix_sum(N % {p_len})",
                    "formula_at_N_minus_1": f"{var}_0 + ((N - 1) // {p_len}) * {p_sum} + prefix_sum((N - 1) % {p_len})"
                }
        for var, const_val in getattr(self.summary, 'constant_sets', {}).items():
            if var not in formulas:
                formulas[var] = {
                    "constant": const_val,
                    "formula_at_N": str(const_val),
                    "formula_at_N_minus_1": str(const_val)
                }
        for var, shift_info in getattr(self.summary, 'geometric_shifts', {}).items():
            if var not in formulas:
                base = shift_info.get('base', 2)
                src_desc = shift_info.get('var', shift_info.get('val', 1))
                formulas[var] = {
                    "type": "geometric",
                    "geometric_shift": shift_info,
                    "formula_at_N": f"{var}_0 + ({base}^N - 1) * {src_desc}",
                    "formula_at_N_minus_1": f"{var}_0 + ({base}^(N-1) - 1) * {src_desc}"
                }
        return formulas

    def get_exit_invariant_rule(self) -> str:
        """
        The fundamental Iron Constraint:
        A loop terminating strictly at iteration N requires:
        1. ExitCondition(State(N)) == True  [The exit branch is taken / header condition fails]
        2. ExitCondition(State(N-1)) == False for N > 0  [The loop was NOT exited prematurely at iteration N-1]
        """
        cond_str = self.summary.exit_condition or "Unknown Exit"
        return (
            f"Iron Constraint: Enforce [{cond_str}] evaluated at State(N) == True "
            f"AND Implies(N > 0, [{cond_str}] evaluated at State(N-1) == False)"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the invariant contract into a standard dictionary/JSON format."""
        exit_instructions = []
        for r in getattr(self.summary, 'exit_records', []):
            if hasattr(r, 'mnemonic'):
                exit_instructions.append({
                    "address": getattr(r, 'address', 0),
                    "mnemonic": getattr(r, 'mnemonic', ''),
                    "op_str": getattr(r, 'op_str', ''),
                    "jump_taken": getattr(r, 'jump_taken', False)
                })
        return {
            "exit_condition_text": self.summary.exit_condition,
            "exit_instructions": exit_instructions,
            "induction_formulas": self.get_induction_formulas(),
            "iron_constraint_rule": self.get_exit_invariant_rule(),
            "iterations_bound": self.summary.iterations
        }
