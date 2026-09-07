"""
Strilight Code Generation Subsystem (strilight.frontend.codegen)
==================================================================
Lightweight, multi-language code generation adapter that translates
`VariableLoopExpr` and `LoopSummary` mathematical models into clean,
idiomatic, O(1) executable Python and C/C++ code with full variable name preservation
and symbolic variable expression support.
"""

import ast
from fractions import Fraction
from typing import Dict, List, Any, Optional, Callable
from strilight.engine.vsa.models import (
    VariableLoopExpr,
    LoopSummary,
    LinearTerm,
    PeriodicTerm,
    GeometricTerm,
    TelescopingTerm,
    PowerScale,
    IdentityScale,
)


class CodeGenerator:
    """
    Translates mathematical loop expressions and summaries into high-level code
    with support for exact variable name preservation and in-place statement generation.
    """

    @classmethod
    def to_python_expr_str(
        cls,
        expr: VariableLoopExpr,
        N_var: str = "N",
        preserve_names: bool = True
    ) -> str:
        """
        Emits an O(1) Python mathematical expression string for a single VariableLoopExpr.
        """
        if expr.constant_val is not None:
            return str(expr.constant_val)

        init_name = expr.name if preserve_names else f"{expr.name}_0"
        scale_parts = []

        # Multiplicative scale kernel
        if isinstance(expr.scale_kernel, PowerScale):
            scale_parts.append(f"({expr.scale_kernel.base} ** {N_var}) * {init_name}")
        else:
            scale_parts.append(init_name)

        term_parts = []
        for term in expr.terms:
            if isinstance(term, LinearTerm):
                if term.scale_var:
                    if term.stride == 1:
                        term_parts.append(f"({term.scale_var}) * {N_var}")
                    else:
                        term_parts.append(f"{term.stride} * ({term.scale_var}) * {N_var}")
                elif term.stride >= 0:
                    term_parts.append(f"{term.stride} * {N_var}")
                else:
                    term_parts.append(f"({term.stride}) * {N_var}")

            elif isinstance(term, PeriodicTerm):
                P = len(term.pattern)
                cycle_sum = sum(term.pattern)
                if P > 0:
                    scale_mult = f" * {term.scale_var}" if term.scale_var else ""
                    prefix_sums = [0]
                    cur = 0
                    for x in term.pattern[:-1]:
                        cur += x
                        prefix_sums.append(cur)
                    prefix_tuple = tuple(prefix_sums)
                    if all(p == 0 for p in prefix_sums):
                        term_parts.append(f"(({N_var} // {P}) * {cycle_sum}{scale_mult})")
                    else:
                        term_parts.append(f"(({N_var} // {P}) * {cycle_sum}{scale_mult} + {prefix_tuple}[({N_var}) % {P}]{scale_mult})")

            elif isinstance(term, GeometricTerm):
                term_parts.append(f"(({term.base} ** {N_var} - 1) * {term.val})")

            elif isinstance(term, TelescopingTerm):
                cascade = term.cascade
                P = len(cascade.branches)
                if P > 0:
                    branch_deltas = [b.deltas.get(term.target_var, 0) for b in cascade.branches]
                    cycle_sum = sum(branch_deltas)
                    term_parts.append(f"(({N_var} // {P}) * {cycle_sum})")

        all_parts = scale_parts + term_parts
        return " + ".join(all_parts) if all_parts else init_name

    @classmethod
    def to_c_expr_str(
        cls,
        expr: VariableLoopExpr,
        N_var: str = "N",
        preserve_names: bool = True
    ) -> str:
        """
        Emits an O(1) C mathematical expression string for a single VariableLoopExpr.
        """
        if expr.constant_val is not None:
            return str(expr.constant_val)

        init_name = expr.name if preserve_names else f"{expr.name}_0"
        scale_parts = []

        if isinstance(expr.scale_kernel, PowerScale):
            if expr.scale_kernel.base == 2:
                scale_parts.append(f"(1ULL << {N_var}) * {init_name}")
            else:
                scale_parts.append(f"pow({expr.scale_kernel.base}, {N_var}) * {init_name}")
        else:
            scale_parts.append(init_name)

        term_parts = []
        for term in expr.terms:
            if isinstance(term, LinearTerm):
                if term.scale_var:
                    if term.stride == 1:
                        term_parts.append(f"(({term.scale_var}) * {N_var})")
                    else:
                        term_parts.append(f"({term.stride}LL * ({term.scale_var}) * {N_var})")
                else:
                    term_parts.append(f"({term.stride}LL * {N_var})")

            elif isinstance(term, PeriodicTerm):
                P = len(term.pattern)
                cycle_sum = sum(term.pattern)
                if P > 0:
                    scale_mult = f" * {term.scale_var}" if term.scale_var else ""
                    term_parts.append(f"(({N_var} / {P}) * {cycle_sum}{scale_mult})")

            elif isinstance(term, GeometricTerm):
                if term.base == 2:
                    term_parts.append(f"(((1ULL << {N_var}) - 1) * {term.val})")
                else:
                    term_parts.append(f"((pow({term.base}, {N_var}) - 1) * {term.val})")

            elif isinstance(term, TelescopingTerm):
                cascade = term.cascade
                P = len(cascade.branches)
                if P > 0:
                    branch_deltas = [b.deltas.get(term.target_var, 0) for b in cascade.branches]
                    cycle_sum = sum(branch_deltas)
                    term_parts.append(f"(({N_var} / {P}) * {cycle_sum})")

        all_parts = scale_parts + term_parts
        return " + ".join(all_parts) if all_parts else init_name

    @classmethod
    def to_python_statements(
        cls,
        summary: LoopSummary,
        N_var: str = "N",
        in_place: bool = True
    ) -> str:
        """
        Emits clean in-place Python statements (e.g. `acc += (15 * k1 + 2 * k2 + 10) * N`)
        that can be dropped directly inside an existing Python function.
        """
        # 0. Multi-capsule Block-Diagonal Decoupled Code Emission (Rule 14.c & 14.d)
        if getattr(summary, 'capsules', None) and len(summary.capsules) > 1:
            decoupled_stmts = []
            for cap in summary.capsules:
                cap_summary = LoopSummary()
                cap_summary.iterations = summary.iterations
                cap_summary.symbolic_iterations = summary.symbolic_iterations
                cap_summary.coupling_matrix = cap.internal_matrix
                decoupled_stmts.append(
                    f"# Decoupled Block: {cap.name} (DOF={cap.dim}, D_int={cap.interface_dof})\n"
                    + cls.to_python_statements(cap_summary, N_var=N_var, in_place=in_place)
                )
            return "\n\n".join(decoupled_stmts)

        # 0.5. Orbit-Perturbation Closed-Form Emission (Rule 13)
        if getattr(summary, 'orbit_system', None) is not None:
            osys = summary.orbit_system
            lines = [f"# Rule 13: Orbit-Perturbation Closed-Form Carrier ({osys.carrier.name}) in O(1)"]
            if getattr(osys, 'target_collection', None):
                col = osys.target_collection
                lines.append(f"if '{col}' in locals():")
                lines.append(f"    _dt_val = dt if 'dt' in locals() else 0.01")
                lines.append(f"    try:")
                lines.append(f"        {col}[:] = _strilight_orbit_system.eval_multi_body_state({N_var}, {col}, _dt_val)")
                lines.append(f"    except NameError:")
                lines.append(f"        from strilight.engine.vsa.models import OrbitPerturbationSystem, OrbitCarrierDescriptor")
                lines.append(f"        _orbit_sys = OrbitPerturbationSystem(OrbitCarrierDescriptor('dynamic', None))")
                lines.append(f"        {col}[:] = _orbit_sys.eval_multi_body_state({N_var}, {col}, _dt_val)")
                return "\n".join(lines)
            elif osys.carrier.angular_frequency is not None and osys.carrier.harmonic_pairs:
                lines.append(f"sl_theta = {osys.carrier.angular_frequency} * ({N_var})")
                lines.append("sl_cos_t = math.cos(sl_theta)")
                lines.append("sl_sin_t = math.sin(sl_theta)")
                for x_var, y_var in osys.carrier.harmonic_pairs:
                    lines.append(f"final_{x_var} = {x_var} * sl_cos_t - {y_var} * sl_sin_t")
                    lines.append(f"final_{y_var} = {x_var} * sl_sin_t + {y_var} * sl_cos_t")
                    lines.append(f"{x_var} = final_{x_var}")
                    lines.append(f"{y_var} = final_{y_var}")

            if osys.perturbation and getattr(osys, 'target_collection', None) != "bodies":
                stride = osys.perturbation.epoch_stride
                k_start = osys.perturbation.k_start
                lines.append(f"sl_k_epoch = max(0, ({N_var} - {k_start}) // {stride}) if ({N_var}) >= {k_start} else 0")
                for r_var in osys.perturbation.reversal_vars:
                    e = osys.perturbation.restitution_coeff
                    lines.append(f"sl_sign_{r_var} = (-1.0 if (sl_k_epoch % 2 == 1) else 1.0) * ({e} ** sl_k_epoch)")
                    lines.append(f"{r_var} *= sl_sign_{r_var}")
                for i_var, delta in osys.perturbation.impulse_vector.items():
                    lines.append(f"{i_var} += sl_k_epoch * {delta}")
                for s_var, drift in osys.perturbation.secular_drift.items():
                    lines.append(f"{s_var} += sl_k_epoch * {drift}")
            return "\n".join(lines)

        # 1. Handle Coupled Matrix Recurrences (Rule 7)
        if summary.coupling_matrix and not summary.coupling_matrix.is_identity():
            is_concrete = False
            N_val = None
            try:
                N_val = int(N_var)
                is_concrete = True
            except ValueError:
                if summary.iterations is not None:
                    N_val = summary.iterations
                    is_concrete = True

            vars_list = summary.coupling_matrix.vars
            dim = summary.coupling_matrix.dim
            aug = summary.coupling_matrix.to_augmented_matrix()
            n = len(aug)
            has_rational = any(isinstance(x, (Fraction, float)) for row in aug for x in row)

            if is_concrete and N_val is not None:
                M_pow = summary.coupling_matrix.pow_mod(N_val)
                stmts = []
                for i, v in enumerate(vars_list):
                    terms = []
                    for j, src in enumerate(vars_list):
                        coeff = M_pow.matrix[i][j]
                        if coeff == 1:
                            terms.append(src)
                        elif coeff != 0:
                            if isinstance(coeff, int) and coeff > 9:
                                terms.append(f"0x{coeff:08X} * {src}")
                            elif isinstance(coeff, Fraction):
                                terms.append(f"Fraction({coeff.numerator}, {coeff.denominator}) * {src}")
                            else:
                                terms.append(f"{coeff} * {src}")
                    if M_pow.offset[i] != 0:
                        off = M_pow.offset[i]
                        if isinstance(off, int) and off > 9:
                            terms.append(f"0x{off:08X}")
                        elif isinstance(off, Fraction):
                            terms.append(f"Fraction({off.numerator}, {off.denominator})")
                        else:
                            terms.append(str(off))
                    stmts.append(f"final_{v} = ({' + '.join(terms) if terms else '0'})")
                stmts.append(f"{', '.join(vars_list)} = {', '.join(f'final_{v}' for v in vars_list)}")
                return "\n".join(stmts)
            else:
                # Dynamic runtime N -> Emit fast O(log N) Binary Exponentiation block
                base_init = str(aug)
                mod_apply = "" if has_rational else " % sl_mod"
                mod_decl = "" if has_rational else "sl_mod = 2**32\n"

                py_block = f"""# Fast O(log {N_var}) Binary Matrix Exponentiation Engine
{mod_decl}sl_base = {base_init}
sl_res = [[int(i == j) for j in range({n})] for i in range({n})]
sl_p = {N_var}

while sl_p > 0:
    if sl_p & 1:
        sl_tmp = [[0] * {n} for _ in range({n})]
        for i in range({n}):
            for k in range({n}):
                r_ik = sl_res[i][k]
                if r_ik != 0:
                    for j in range({n}):
                        sl_tmp[i][j] = (sl_tmp[i][j] + r_ik * sl_base[k][j]){mod_apply}
        sl_res = sl_tmp
    sl_tmp_b = [[0] * {n} for _ in range({n})]
    for i in range({n}):
        for k in range({n}):
            b_ik = sl_base[i][k]
            if b_ik != 0:
                for j in range({n}):
                    sl_tmp_b[i][j] = (sl_tmp_b[i][j] + b_ik * sl_base[k][j]){mod_apply}
    sl_base = sl_tmp_b
    sl_p >>= 1\n\n"""
                calc_stmts = []
                for i, v in enumerate(vars_list):
                    calc_terms = [f"sl_res[{i}][{j}] * {vars_list[j]}" for j in range(dim)]
                    calc_terms.append(f"sl_res[{i}][{dim}]")
                    calc_stmts.append(f"final_{v} = ({' + '.join(calc_terms)}){mod_apply}")
                calc_stmts.append(f"{', '.join(vars_list)} = {', '.join(f'final_{v}' for v in vars_list)}")
                return py_block + "\n".join(calc_stmts)

        stmts = []
        for v in sorted(summary.var_exprs.keys()):
            expr = summary.var_exprs[v]
            if expr.constant_val is not None:
                stmts.append(f"{v} = {expr.constant_val}")
                continue

            is_pure_identity = isinstance(expr.scale_kernel, IdentityScale) or expr.scale_kernel is None
            if in_place and is_pure_identity:
                delta_parts = []
                for term in expr.terms:
                    if isinstance(term, LinearTerm):
                        stride_str = f"Fraction({term.stride.numerator}, {term.stride.denominator})" if isinstance(term.stride, Fraction) else str(term.stride)
                        if term.scale_var:
                            if term.stride == 1:
                                delta_parts.append(f"({term.scale_var}) * {N_var}")
                            else:
                                delta_parts.append(f"{stride_str} * ({term.scale_var}) * {N_var}")
                        else:
                            delta_parts.append(f"{stride_str} * {N_var}")
                    elif isinstance(term, PeriodicTerm):
                        P = len(term.pattern)
                        cycle_sum = sum(term.pattern)
                        scale_mult = f" * {term.scale_var}" if term.scale_var else ""
                        if P > 0:
                            prefix_sums = [0]
                            cur = 0
                            for x in term.pattern[:-1]:
                                cur += x
                                prefix_sums.append(cur)
                            prefix_tuple = tuple(prefix_sums)
                            if all(p == 0 for p in prefix_sums):
                                delta_parts.append(f"({N_var} // {P}) * {cycle_sum}{scale_mult}")
                            else:
                                delta_parts.append(f"(({N_var} // {P}) * {cycle_sum}{scale_mult} + {prefix_tuple}[({N_var}) % {P}]{scale_mult})")
                    elif isinstance(term, GeometricTerm):
                        delta_parts.append(f"({term.base} ** {N_var} - 1) * {term.val}")
                    elif isinstance(term, TelescopingTerm):
                        cascade = term.cascade
                        P = len(cascade.branches)
                        branch_deltas = [b.deltas.get(term.target_var, 0) for b in cascade.branches]
                        cycle_sum = sum(branch_deltas)
                        delta_parts.append(f"({N_var} // {P}) * {cycle_sum}")

                if delta_parts:
                    stmts.append(f"{v} += {' + '.join(delta_parts)}")
                else:
                    stmts.append(f"# {v} is invariant")
            else:
                expr_str = cls.to_python_expr_str(expr, N_var=N_var, preserve_names=True)
        # In-Place Array Slice Mutations (Rule 8.f)
        for arr_name, mut in getattr(summary, 'array_mutations', {}).items():
            if mut.kind == "constant":
                stmts.append(f"{arr_name}[:{N_var}] = [{mut.constant_val}] * ({N_var})")
            elif mut.kind == "affine":
                if mut.stride == 1:
                    stmts.append(f"{arr_name}[:{N_var}] = list(range({mut.base}, {mut.base} + ({N_var})))")
                else:
                    stmts.append(f"{arr_name}[:{N_var}] = list(range({mut.base}, {mut.base} + ({N_var}) * {mut.stride}, {mut.stride}))")
            elif mut.kind == "accumulate":
                if mut.delta >= 0:
                    stmts.append(f"{arr_name}[:{N_var}] = [x + {mut.delta} for x in {arr_name}[:{N_var}]]")
                else:
                    stmts.append(f"{arr_name}[:{N_var}] = [x - {-mut.delta} for x in {arr_name}[:{N_var}]]")

        return "\n".join(stmts)

    @classmethod
    def to_c_statements(
        cls,
        summary: LoopSummary,
        N_var: str = "N",
        in_place: bool = True
    ) -> str:
        """
        Emits clean in-place C statements (e.g. `acc += ((15 * k1 + 10) * N) + ((k2 * 2) * N);`)
        that can be dropped directly inside an existing C function.
        """
        # 0. Multi-capsule Block-Diagonal Decoupled Code Emission (Rule 14.c & 14.d)
        if getattr(summary, 'capsules', None) and len(summary.capsules) > 1:
            decoupled_c = []
            for cap in summary.capsules:
                cap_summary = LoopSummary()
                cap_summary.iterations = summary.iterations
                cap_summary.symbolic_iterations = summary.symbolic_iterations
                cap_summary.coupling_matrix = cap.internal_matrix
                decoupled_c.append(
                    f"/* Decoupled Block: {cap.name} (DOF={cap.dim}, D_int={cap.interface_dof}) */\n"
                    + cls.to_c_statements(cap_summary, N_var=N_var, in_place=in_place)
                )
            return "\n\n".join(decoupled_c)

        # 0.5. Orbit-Perturbation Closed-Form Emission (Rule 13)
        if getattr(summary, 'orbit_system', None) is not None:
            osys = summary.orbit_system
            lines = [f"/* Rule 13: Orbit-Perturbation Closed-Form Carrier ({osys.carrier.name}) in O(1) */"]
            if osys.carrier.angular_frequency is not None and osys.carrier.harmonic_pairs:
                lines.append(f"double sl_theta = {osys.carrier.angular_frequency} * ({N_var});")
                lines.append("double sl_cos_t = cos(sl_theta);")
                lines.append("double sl_sin_t = sin(sl_theta);")
                for x_var, y_var in osys.carrier.harmonic_pairs:
                    lines.append(f"double final_{x_var} = {x_var} * sl_cos_t - {y_var} * sl_sin_t;")
                    lines.append(f"double final_{y_var} = {x_var} * sl_sin_t + {y_var} * sl_cos_t;")
                    lines.append(f"{x_var} = final_{x_var};")
                    lines.append(f"{y_var} = final_{y_var};")

            if osys.perturbation:
                stride = osys.perturbation.epoch_stride
                k_start = osys.perturbation.k_start
                lines.append(f"int64_t sl_k_epoch = ({N_var} >= {k_start}) ? (({N_var} - {k_start}) / {stride}) : 0;")
                for r_var in osys.perturbation.reversal_vars:
                    e = osys.perturbation.restitution_coeff
                    lines.append(f"double sl_sign_{r_var} = ((sl_k_epoch % 2 == 1) ? -1.0 : 1.0) * pow({e}, (double)sl_k_epoch);")
                    lines.append(f"{r_var} *= sl_sign_{r_var};")
                for i_var, delta in osys.perturbation.impulse_vector.items():
                    lines.append(f"{i_var} += sl_k_epoch * {delta};")
                for s_var, drift in osys.perturbation.secular_drift.items():
                    lines.append(f"{s_var} += sl_k_epoch * {drift};")
            return "\n".join(lines)

        # 1. Handle Coupled Matrix Recurrences (Rule 7)
        if summary.coupling_matrix and not summary.coupling_matrix.is_identity():
            is_concrete = False
            N_val = None
            try:
                N_val = int(N_var)
                is_concrete = True
            except ValueError:
                if summary.iterations is not None:
                    N_val = summary.iterations
                    is_concrete = True

            vars_list = summary.coupling_matrix.vars
            dim = summary.coupling_matrix.dim
            aug = summary.coupling_matrix.to_augmented_matrix()
            n = len(aug)

            if is_concrete and N_val is not None:
                M_pow = summary.coupling_matrix.pow_mod(N_val)
                stmts = []
                for i, v in enumerate(vars_list):
                    terms = []
                    for j, src in enumerate(vars_list):
                        coeff = M_pow.matrix[i][j]
                        if coeff == 1:
                            terms.append(src)
                        elif coeff != 0:
                            if isinstance(coeff, int) and coeff > 9:
                                terms.append(f"0x{coeff:08X} * {src}")
                            elif isinstance(coeff, Fraction):
                                terms.append(f"({coeff.numerator}.0 / {coeff.denominator}.0) * {src}")
                            else:
                                terms.append(f"{coeff} * {src}")
                    if M_pow.offset[i] != 0:
                        off = M_pow.offset[i]
                        if isinstance(off, int) and off > 9:
                            terms.append(f"0x{off:08X}")
                        elif isinstance(off, Fraction):
                            terms.append(f"({off.numerator}.0 / {off.denominator}.0)")
                        else:
                            terms.append(str(off))
                    v_ident = v.replace("->", "_").replace(".", "_").replace("[", "_").replace("]", "_")
                    v_type = "double" if any(isinstance(x, (Fraction, float)) for x in M_pow.matrix[i] + [M_pow.offset[i]]) else "uint32_t"
                    stmts.append(f"{v_type} final_{v_ident} = ({' + '.join(terms) if terms else '0'});")
                for v in vars_list:
                    v_ident = v.replace("->", "_").replace(".", "_").replace("[", "_").replace("]", "_")
                    stmts.append(f"{v} = final_{v_ident};")
                return "\n".join(stmts)
            else:
                # Dynamic runtime N -> Emit fast O(log N) Binary Exponentiation block
                has_frac = any(isinstance(x, (Fraction, float)) for row in aug for x in row)
                mat_type = "double" if has_frac else "uint32_t"

                base_rows = []
                for row in aug:
                    base_rows.append("{" + ", ".join(f"0x{x:08X}" if (isinstance(x, int) and x > 9) else (f"({x.numerator}.0/{x.denominator}.0)" if isinstance(x, Fraction) else str(x)) for x in row) + "}")
                base_init = ",\n    ".join(base_rows)
                res_rows = []
                for i in range(n):
                    res_rows.append("{" + ", ".join("1" if i == j else "0" for j in range(n)) + "}")
                res_init = "{\n    " + ",\n    ".join(res_rows) + "\n}"

                c_block = f"""// Fast O(log {N_var}) Binary Matrix Exponentiation Engine (Row-Major Optimized)
{mat_type} sl_base[{n}][{n}] = {{
    {base_init}
}};
{mat_type} sl_res[{n}][{n}] = {res_init};
uint64_t sl_p = (uint64_t)({N_var});

while (sl_p > 0) {{
    if (sl_p & 1) {{
        {mat_type} sl_tmp[{n}][{n}] = {{0}};
        for (int i = 0; i < {n}; i++) {{
            for (int k = 0; k < {n}; k++) {{
                {mat_type} r_ik = sl_res[i][k];
                if (r_ik != 0) {{
                    for (int j = 0; j < {n}; j++) {{
                        sl_tmp[i][j] += r_ik * sl_base[k][j];
                    }}
                }}
            }}
        }}
        for (int i = 0; i < {n}; i++)
            for (int j = 0; j < {n}; j++)
                sl_res[i][j] = sl_tmp[i][j];
    }}
    {mat_type} sl_tmp_b[{n}][{n}] = {{0}};
    for (int i = 0; i < {n}; i++) {{
        for (int k = 0; k < {n}; k++) {{
            {mat_type} b_ik = sl_base[i][k];
            if (b_ik != 0) {{
                for (int j = 0; j < {n}; j++) {{
                    sl_tmp_b[i][j] += b_ik * sl_base[k][j];
                }}
            }}
        }}
    }}
    for (int i = 0; i < {n}; i++)
        for (int j = 0; j < {n}; j++)
            sl_base[i][j] = sl_tmp_b[i][j];
    sl_p >>= 1;
}}\n\n"""
                calc_stmts = []
                for i, v in enumerate(vars_list):
                    calc_terms = [f"sl_res[{i}][{j}] * {vars_list[j]}" for j in range(dim)]
                    calc_terms.append(f"sl_res[{i}][{dim}]")
                    v_ident = v.replace("->", "_").replace(".", "_").replace("[", "_").replace("]", "_")
                    calc_stmts.append(f"{mat_type} final_{v_ident} = ({' + '.join(calc_terms)});")
                for v in vars_list:
                    v_ident = v.replace("->", "_").replace(".", "_").replace("[", "_").replace("]", "_")
                    calc_stmts.append(f"{v} = final_{v_ident};")

                return c_block + "\n".join(calc_stmts)

        stmts = []
        for v in sorted(summary.var_exprs.keys()):
            expr = summary.var_exprs[v]
            if expr.constant_val is not None:
                stmts.append(f"{v} = {expr.constant_val};")
                continue

            is_pure_identity = isinstance(expr.scale_kernel, IdentityScale) or expr.scale_kernel is None
            if in_place and is_pure_identity:
                delta_parts = []
                for term in expr.terms:
                    if isinstance(term, LinearTerm):
                        if isinstance(term.stride, Fraction):
                            stride_str = f"({term.stride.numerator}.0 / {term.stride.denominator}.0)"
                        else:
                            stride_str = f"{term.stride}LL"
                        if term.scale_var:
                            if term.stride == 1:
                                delta_parts.append(f"(({term.scale_var}) * {N_var})")
                            else:
                                delta_parts.append(f"({stride_str} * ({term.scale_var}) * {N_var})")
                        else:
                            delta_parts.append(f"({stride_str} * {N_var})")
                    elif isinstance(term, PeriodicTerm):
                        P = len(term.pattern)
                        cycle_sum = sum(term.pattern)
                        scale_mult = f" * {term.scale_var}" if term.scale_var else ""
                        delta_parts.append(f"(({N_var} / {P}) * {cycle_sum}{scale_mult})")
                    elif isinstance(term, GeometricTerm):
                        if term.base == 2:
                            delta_parts.append(f"(((1ULL << {N_var}) - 1) * {term.val})")
                        else:
                            delta_parts.append(f"((pow({term.base}, {N_var}) - 1) * {term.val})")
                    elif isinstance(term, TelescopingTerm):
                        cascade = term.cascade
                        P = len(cascade.branches)
                        branch_deltas = [b.deltas.get(term.target_var, 0) for b in cascade.branches]
                        cycle_sum = sum(branch_deltas)
                        delta_parts.append(f"(({N_var} / {P}) * {cycle_sum})")

                if delta_parts:
                    stmts.append(f"{v} += {' + '.join(delta_parts)};")
                else:
                    stmts.append(f"/* {v} is invariant */")
            else:
                expr_str = cls.to_c_expr_str(expr, N_var=N_var, preserve_names=True)
                stmts.append(f"{v} = {expr_str};")

        # In-Place Array Slice Mutations for C (Rule 8.f)
        for arr_name, mut in getattr(summary, 'array_mutations', {}).items():
            is_struct = "." in arr_name
            if is_struct:
                base_arr, field = arr_name.split(".", 1)
                slot = f"{base_arr}[_i].{field}"
            else:
                base_arr = arr_name
                slot = f"{arr_name}[_i]"

            if mut.kind == "constant":
                if mut.constant_val == 0 and not is_struct:
                    stmts.append(f"memset({arr_name}, 0, ({N_var}) * sizeof({arr_name}[0]));")
                else:
                    stmts.append(f"for (int _i = 0; _i < ({N_var}); _i++) {{ {slot} = {mut.constant_val}; }}")
            elif mut.kind == "affine":
                if mut.stride == 1:
                    stmts.append(f"for (int _i = 0; _i < ({N_var}); _i++) {{ {slot} = {mut.base} + _i; }}")
                else:
                    stmts.append(f"for (int _i = 0; _i < ({N_var}); _i++) {{ {slot} = {mut.base} + _i * {mut.stride}; }}")
            elif mut.kind == "accumulate":
                if mut.delta >= 0:
                    stmts.append(f"for (int _i = 0; _i < ({N_var}); _i++) {{ {slot} += {mut.delta}; }}")
                else:
                    stmts.append(f"for (int _i = 0; _i < ({N_var}); _i++) {{ {slot} -= {-mut.delta}; }}")

        return "\n".join(stmts)

    @classmethod
    def to_python_code(
        cls,
        summary: LoopSummary,
        func_name: str = "accelerated_loop",
        N_var: str = "N",
        preserve_names: bool = True
    ) -> str:
        """
        Emits a complete, formatted Python function implementing the closed-form loop in O(1).
        Preserves original variable names by default.
        """
        var_names = sorted(summary.var_exprs.keys())
        params = [N_var] + (var_names if preserve_names else [f"{v}_0" for v in var_names])
        
        assign_lines = []
        for v in var_names:
            expr_str = cls.to_python_expr_str(summary.var_exprs[v], N_var=N_var, preserve_names=preserve_names)
            var_out = v if preserve_names else f"{v}_final"
            assign_lines.append(f"    {var_out} = {expr_str}")

        ret_dict = ", ".join(f"'{v}': {v if preserve_names else f'{v}_final'}" for v in var_names)
        
        func_template = f"def {func_name}({', '.join(params)}):\n"
        if assign_lines:
            func_template += "\n".join(assign_lines) + "\n"
            func_template += f"    return {{{ret_dict}}}\n"
        else:
            func_template += "    return {}\n"

        parsed_ast = ast.parse(func_template)
        return ast.unparse(parsed_ast)

    @classmethod
    def to_python_callable(
        cls,
        summary: LoopSummary,
        func_name: str = "accelerated_loop",
        N_var: str = "N",
        preserve_names: bool = True
    ) -> Callable:
        """
        Compiles the O(1) closed-form Python function into an in-memory executable callable.
        """
        code_str = cls.to_python_code(summary, func_name=func_name, N_var=N_var, preserve_names=preserve_names)
        local_env: Dict[str, Any] = {}
        exec(code_str, {}, local_env)
        return local_env[func_name]

    @classmethod
    def to_c_code(
        cls,
        summary: LoopSummary,
        func_name: str = "accelerated_loop",
        N_var: str = "N",
        preserve_names: bool = True
    ) -> str:
        """
        Emits a clean C function implementing the closed-form loop in O(1).
        Preserves original variable names in parameter list.
        """
        var_names = sorted(summary.var_exprs.keys())
        params = [f"uint64_t {N_var}"] + [f"uint64_t {v if preserve_names else f'{v}_0'}" for v in var_names]

        c_lines = [
            f"#include <stdint.h>",
            f"",
            f"typedef struct {{",
        ]
        for v in var_names:
            c_lines.append(f"    uint64_t {v};")
        c_lines.append(f"}} {func_name}_result_t;")
        c_lines.append(f"")
        c_lines.append(f"{func_name}_result_t {func_name}({', '.join(params)}) {{")
        c_lines.append(f"    {func_name}_result_t res;")
        for v in var_names:
            expr_str = cls.to_c_expr_str(summary.var_exprs[v], N_var=N_var, preserve_names=preserve_names)
            c_lines.append(f"    res.{v} = {expr_str};")
        c_lines.append(f"    return res;")
        c_lines.append(f"}}")
        return "\n".join(c_lines)
