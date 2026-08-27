import copy
import logging
from typing import Dict, Optional, List, Any, Tuple, Callable, Set, TYPE_CHECKING
import z3

if TYPE_CHECKING:
    from strilight.engine.tracker import TraceRecord

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
    Scalar Stride Component:
        Delta_scalar(N) = stride * N
    """
    def __init__(self, stride: int):
        self.stride = stride

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        s_val = z3.BitVecVal(self.stride, bit_size)
        return s_val * N_ast, s_val * N_prev_ast

    def to_induction_formula(self, var_name: str) -> Dict[str, Any]:
        return {
            "type": "linear",
            "delta": self.stride,
            "stride": self.stride,
            "formula_at_N": f"{var_name}_0 + ({self.stride}) * N",
            "formula_at_N_minus_1": f"{var_name}_0 + ({self.stride}) * (N - 1)"
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "linear", "stride": self.stride}


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
    def __init__(self, target_reg: str, branches: Optional[List[TelescopingBranch]] = None):
        self.target_reg = target_reg
        self.branches: List[TelescopingBranch] = list(branches or [])

    def add_branch(self, branch: TelescopingBranch) -> None:
        self.branches.append(branch)

    def is_partition_of_unity(self) -> bool:
        return len(self.branches) > 0

    def get_telescoping_formula(self) -> str:
        terms = []
        for k, b in enumerate(self.branches):
            d = b.deltas.get(self.target_reg, 0)
            terms.append(f"P_{k+1}({b.name}) * ({d})")
        return " + ".join(terms) if terms else "0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_reg": self.target_reg,
            "branches": [b.to_dict() for b in self.branches],
            "telescoping_formula": self.get_telescoping_formula(),
            "partition_of_unity": self.is_partition_of_unity(),
        }


class TelescopingTerm(LoopTerm):
    """
    Telescoping Cascade Component for M Conditions:
        Delta_tele(N) = N * sum_{k=1}^M (P_k * Delta_k)
    """
    def __init__(self, cascade: TelescopingCascade, target_reg: Optional[str] = None):
        self.cascade = cascade
        self.target_reg = target_reg or cascade.target_reg

    def to_smt(
        self,
        N_ast: z3.BitVecRef,
        N_prev_ast: z3.BitVecRef,
        resolve_val_fn: Callable[[Any], Optional[z3.BitVecRef]],
        bit_size: int = 64
    ) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        from strilight.engine.vsa.smt_translator import LoopSMTTranslator
        return LoopSMTTranslator.build_telescoping_cascade_ast(
            N_ast, N_prev_ast, self.target_reg, self.cascade, resolve_val_fn=resolve_val_fn
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
            "target_reg": self.target_reg
        }


# ============================================================================
# 3. Universal Loop Expression Tree AST: RegisterLoopExpr
# ============================================================================

class RegisterLoopExpr:
    """
    Universal Loop Expression Tree AST for a Single Register or Memory Target.
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

    def add_term(self, term: LoopTerm) -> 'RegisterLoopExpr':
        self.terms.append(term)
        return self

    def set_constant(self, val: int) -> 'RegisterLoopExpr':
        self.constant_val = val
        self.terms.clear()
        self.scale_kernel = IdentityScale()
        return self

    def set_scale(self, scale_kernel: ScaleKernel) -> 'RegisterLoopExpr':
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


# ============================================================================
# 4. Affine Expressions & Coupling Matrix (Rule 7)
# ============================================================================

class AffineExpr:
    """
    Represents an affine symbolic linear combination of registers and integer offsets:
        Expr = sum(coeff * reg) + offset
    """
    def __init__(self, coeffs: Optional[Dict[str, int]] = None, offset: int = 0):
        self.coeffs: Dict[str, int] = {k: v for k, v in (coeffs or {}).items() if v != 0}
        self.offset: int = offset

    @classmethod
    def from_reg(cls, reg: str) -> 'AffineExpr':
        return cls(coeffs={reg: 1}, offset=0)

    @classmethod
    def from_const(cls, val: int) -> 'AffineExpr':
        return cls(coeffs={}, offset=val)

    def add(self, other: 'AffineExpr') -> 'AffineExpr':
        new_coeffs = dict(self.coeffs)
        for k, v in other.coeffs.items():
            new_coeffs[k] = new_coeffs.get(k, 0) + v
        return AffineExpr(new_coeffs, self.offset + other.offset)

    def sub(self, other: 'AffineExpr') -> 'AffineExpr':
        new_coeffs = dict(self.coeffs)
        for k, v in other.coeffs.items():
            new_coeffs[k] = new_coeffs.get(k, 0) - v
        return AffineExpr(new_coeffs, self.offset - other.offset)

    def mul_const(self, k: int) -> 'AffineExpr':
        new_coeffs = {reg: c * k for reg, c in self.coeffs.items()}
        return AffineExpr(new_coeffs, self.offset * k)

    def __add__(self, other):
        if isinstance(other, AffineExpr):
            return self.add(other)
        elif isinstance(other, int):
            return AffineExpr(self.coeffs, self.offset + other)
        return NotImplemented

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, AffineExpr):
            return self.sub(other)
        elif isinstance(other, int):
            return AffineExpr(self.coeffs, self.offset - other)
        return NotImplemented

    def __mul__(self, other):
        if isinstance(other, int):
            return self.mul_const(other)
        return NotImplemented

    def __rmul__(self, other):
        return self.__mul__(other)

    def is_constant(self) -> bool:
        return len(self.coeffs) == 0

    def is_pure_reg(self, reg: str) -> bool:
        return len(self.coeffs) == 1 and self.coeffs.get(reg) == 1 and self.offset == 0

    def get_scalar_delta(self, reg: str) -> Optional[int]:
        """If this expression evaluates to `reg + c`, returns scalar delta `c`."""
        if len(self.coeffs) == 1 and self.coeffs.get(reg) == 1:
            return self.offset
        return None

    def __repr__(self) -> str:
        parts = [f"{c}*{r}" if c != 1 else r for r, c in self.coeffs.items()]
        if self.offset != 0 or not parts:
            parts.append(str(self.offset))
        return " + ".join(parts)


class RegisterCouplingMatrix:
    """
    Rule 7: Vector State Space and Coupling Matrix (A_coupling).
    Represents the affine state transition:
        R_{k+1} = A * R_k + B
    """
    def __init__(self, regs: List[str]):
        self.regs = list(regs)
        self.reg_to_idx = {r: i for i, r in enumerate(self.regs)}
        self.dim = len(self.regs)
        # Identity matrix initially
        self.matrix = [[1 if i == j else 0 for j in range(self.dim)] for i in range(self.dim)]
        self.offset = [0] * self.dim

    def set_affine_row(self, reg: str, expr: AffineExpr):
        if reg not in self.reg_to_idx:
            return
        row = self.reg_to_idx[reg]
        for j in range(self.dim):
            self.matrix[row][j] = 0
        for src_reg, coeff in expr.coeffs.items():
            if src_reg in self.reg_to_idx:
                self.matrix[row][self.reg_to_idx[src_reg]] = coeff
        self.offset[row] = expr.offset

    def is_identity(self) -> bool:
        for i in range(self.dim):
            for j in range(self.dim):
                expected = 1 if i == j else 0
                if self.matrix[i][j] != expected:
                    return False
        return True


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
        # Universal Symbolic AST Expressions
        self.register_exprs: Dict[str, RegisterLoopExpr] = {}

        # Auto-syncing dictionaries for 100% full backward compatibility
        self.deltas: Dict[str, int] = AutoSyncDict(self._sync_delta)
        self.patterns: Dict[str, List[int]] = AutoSyncDict(self._sync_pattern)
        self.pattern_scales: Dict[str, str] = AutoSyncDict(self._sync_pattern_scale)
        self.constant_sets: Dict[str, int] = AutoSyncDict(self._sync_constant)
        self.geometric_shifts: Dict[str, Dict[str, Any]] = AutoSyncDict(self._sync_geometric)
        self.telescoping_cascades: Dict[str, TelescopingCascade] = AutoSyncDict(self._sync_telescoping)

        self.coupling_matrix: Optional[RegisterCouplingMatrix] = None
        self.exit_condition: Optional[str] = None
        self.exit_records: List['TraceRecord'] = []
        self.exit_guard: Optional[LoopExitGuard] = None
        self.iterations: int = 0
        self.inner_summaries: List['LoopSummary'] = []
        self.direct_deltas: Dict[str, int] = {}
        self.direct_patterns: Dict[str, List[int]] = {}
        self.direct_constant_sets: Dict[str, int] = {}
        self.direct_records: List['TraceRecord'] = []
        self.tick: Optional[int] = None

    def _sync_delta(self, key: str, val: Optional[int]):
        if key not in self.register_exprs:
            self.register_exprs[key] = RegisterLoopExpr(key)
        self.register_exprs[key].terms = [t for t in self.register_exprs[key].terms if not isinstance(t, LinearTerm)]
        if val is not None:
            self.register_exprs[key].add_term(LinearTerm(val))
        elif len(self.register_exprs[key].terms) == 0 and self.register_exprs[key].constant_val is None:
            self.register_exprs.pop(key, None)

    def _sync_pattern(self, key: str, val: Optional[List[int]]):
        if key not in self.register_exprs:
            self.register_exprs[key] = RegisterLoopExpr(key)
        self.register_exprs[key].terms = [t for t in self.register_exprs[key].terms if not isinstance(t, PeriodicTerm)]
        if val is not None:
            scale_var = self.pattern_scales.get(key)
            self.register_exprs[key].add_term(PeriodicTerm(val, scale_var=scale_var))
        elif len(self.register_exprs[key].terms) == 0 and self.register_exprs[key].constant_val is None:
            self.register_exprs.pop(key, None)

    def _sync_pattern_scale(self, key: str, val: Optional[str]):
        if key in self.register_exprs:
            for t in self.register_exprs[key].terms:
                if isinstance(t, PeriodicTerm):
                    t.scale_var = val

    def _sync_constant(self, key: str, val: Optional[int]):
        if key not in self.register_exprs:
            self.register_exprs[key] = RegisterLoopExpr(key)
        if val is not None:
            self.register_exprs[key].set_constant(val)
        else:
            self.register_exprs[key].constant_val = None
            if len(self.register_exprs[key].terms) == 0:
                self.register_exprs.pop(key, None)

    def _sync_geometric(self, key: str, val: Optional[Dict[str, Any]]):
        if key not in self.register_exprs:
            self.register_exprs[key] = RegisterLoopExpr(key)
        self.register_exprs[key].terms = [t for t in self.register_exprs[key].terms if not isinstance(t, GeometricTerm)]
        if val is not None:
            self.register_exprs[key].add_term(GeometricTerm(
                base=val.get('base', 2),
                var=val.get('var'),
                val=val.get('val', 1),
                modulo_bits=val.get('modulo_bits', 0)
            ))
        elif len(self.register_exprs[key].terms) == 0 and self.register_exprs[key].constant_val is None:
            self.register_exprs.pop(key, None)

    def _sync_telescoping(self, key: str, val: Optional[TelescopingCascade]):
        if key not in self.register_exprs:
            self.register_exprs[key] = RegisterLoopExpr(key)
        self.register_exprs[key].terms = [t for t in self.register_exprs[key].terms if not isinstance(t, TelescopingTerm)]
        if val is not None:
            self.register_exprs[key].add_term(TelescopingTerm(val, target_reg=key))
        elif len(self.register_exprs[key].terms) == 0 and self.register_exprs[key].constant_val is None:
            self.register_exprs.pop(key, None)

    @property
    def invariant_contract(self) -> 'LoopInvariantContract':
        """Returns the formal mathematical invariant contract for this loop."""
        return LoopInvariantContract(self)

    def get_invariant_contract(self) -> 'LoopInvariantContract':
        """Helper to retrieve the formal mathematical invariant contract."""
        return LoopInvariantContract(self)


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
