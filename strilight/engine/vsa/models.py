import copy
from typing import Dict, Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from strilight.engine.tracker import TraceRecord


class LoopInvariantContract:
    """
    Explicit mathematical contract for loop invariants and exact termination boundaries.
    Provides closed-form induction formulas for both iteration N and iteration N-1 (the Iron Constraint).
    """
    def __init__(self, summary: 'LoopSummary'):
        self.summary = summary

    def get_induction_formulas(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns the closed-form transition equations for each induction variable:
        - At iteration N: State(N) = State_0 + Delta * N
        - At iteration N-1 (Pre-exit Iron State): State(N-1) = State_0 + Delta * (N - 1)
        """
        formulas = {}
        for var, delta in self.summary.deltas.items():
            formulas[var] = {
                "delta": delta,
                "formula_at_N": f"{var}_0 + ({delta}) * N",
                "formula_at_N_minus_1": f"{var}_0 + ({delta}) * (N - 1)"
            }
        for var, pattern in self.summary.patterns.items():
            p_len = len(pattern)
            p_sum = sum(pattern)
            formulas[var] = {
                "pattern": pattern,
                "period": p_len,
                "cycle_sum": p_sum,
                "formula_at_N": f"{var}_0 + (N // {p_len}) * {p_sum} + prefix_sum(N % {p_len})",
                "formula_at_N_minus_1": f"{var}_0 + ((N - 1) // {p_len}) * {p_sum} + prefix_sum((N - 1) % {p_len})"
            }
        for var, const_val in self.summary.constant_sets.items():
            formulas[var] = {
                "constant": const_val,
                "formula_at_N": str(const_val),
                "formula_at_N_minus_1": str(const_val)
            }
        for var, shift_info in getattr(self.summary, 'geometric_shifts', {}).items():
            base = shift_info.get('base', 2)
            src_desc = shift_info.get('var', shift_info.get('val', 1))
            formulas[var] = {
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


class AffineExpr:
    """
    Represents an affine symbolic linear combination of registers and integer offsets:
        Expr = sum(coeff * reg) + offset
    Phase 1: Symbolic Induction & DAG Expression Tracking.
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


class LoopSummary:
    """
    Symbolic mathematical summary of a loop's effect.
    This is passed to the BackwardTracker (or Translator) to instantly jump over the loop.
    """
    def __init__(self):
        # Maps register name to its extracted symbolic delta per iteration (e.g., EAX increases by 4)
        self.deltas: Dict[str, int] = {}
        
        # Maps register name to periodic polycyclic pattern (e.g., EAX increases by [5, 4, 8, 1])
        self.patterns: Dict[str, List[int]] = {}
        
        # Scaling variables for patterns (e.g. pattern * r10d)
        self.pattern_scales: Dict[str, str] = {}
        
        # Values that are set to a constant and don't change
        self.constant_sets: Dict[str, int] = {}
        
        # Geometric shift recurrences (Rule 6: Positional Receipt, e.g., acc += k2 << i)
        self.geometric_shifts: Dict[str, Dict[str, Any]] = {}
        
        # Coupling matrix (Rule 7)
        self.coupling_matrix: Optional[RegisterCouplingMatrix] = None
        
        # The exit condition string (e.g., "cmp ecx, 10 -> jne")
        self.exit_condition: Optional[str] = None
        
        # Original TraceRecords for the exit condition (e.g. cmp and jcc instructions)
        # to be passed to the Z3 Translator
        self.exit_records: List['TraceRecord'] = []
        
        # The dynamic number of iterations this loop ran
        self.iterations: int = 0
        
        # Nested inner loop summaries
        self.inner_summaries: List['LoopSummary'] = []
        self.direct_deltas: Dict[str, int] = {}
        self.direct_patterns: Dict[str, List[int]] = {}
        self.direct_constant_sets: Dict[str, int] = {}
        self.tick: Optional[int] = None

    @property
    def invariant_contract(self) -> LoopInvariantContract:
        """Returns the formal mathematical invariant contract for this loop."""
        return LoopInvariantContract(self)

    def get_invariant_contract(self) -> LoopInvariantContract:
        """Helper to retrieve the formal mathematical invariant contract."""
        return LoopInvariantContract(self)
