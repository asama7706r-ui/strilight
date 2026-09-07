"""
Strilight Universal Source Lifter Facade (strilight.frontend.source_lifter)
===========================================================================
Pluggable high-level facade that coordinates language-specific lifters
(Python, C, and future languages) and provides source-to-source O(1) acceleration.
"""

import ast
import inspect
import textwrap
import functools
import logging
from typing import Dict, List, Any, Optional, Tuple, Union, Callable

from strilight.engine.vsa.models import LoopSummary
from strilight.frontend.base import BaseLanguageLifter
from strilight.frontend.python import PythonLoopLifter
from strilight.frontend.c import (
    CLoopLifter,
    CForLoopVisitor,
    extract_c_for_block,
    process_c_pragmas,
)
from strilight.frontend.codegen import CodeGenerator
from strilight.frontend.resolver import CrossFileResolver
from strilight.frontend.orbit_matcher import CentralForceOrbitMatcher

logger = logging.getLogger(__name__)


class SourceLifter:
    """
    Universal High-Level Facade for source code analysis and acceleration.
    Automatically dispatches code to language-specific adapters.
    """

    @classmethod
    def lift_python_loop(cls, py_code: str, scope_env: Optional[Dict[str, Any]] = None) -> LoopSummary:
        lifter = PythonLoopLifter(scope_env=scope_env)
        return lifter.lift(py_code)

    @classmethod
    def lift_c_loop(
        cls,
        c_code: str,
        contract: Optional[Any] = None,
        scope_env: Optional[Dict[str, Any]] = None
    ) -> LoopSummary:
        lifter = CLoopLifter()
        return lifter.lift(c_code, contract=contract, scope_env=scope_env)

    @classmethod
    def accelerate_python(
        cls,
        py_code: str,
        in_place: bool = True,
        func_name: str = "accelerated_loop",
        scope_env: Optional[Dict[str, Any]] = None
    ) -> str:
        summary = cls.lift_python_loop(py_code, scope_env=scope_env)
        n_var_name = str(summary.iterations) if summary.iterations is not None else (summary.symbolic_iterations or "N")
        if in_place:
            return CodeGenerator.to_python_statements(summary, N_var=n_var_name)
        param_n = summary.symbolic_iterations or "N"
        return CodeGenerator.to_python_code(summary, func_name=func_name, N_var=param_n, preserve_names=True)

    @classmethod
    def accelerate_c(
        cls,
        c_code: str,
        in_place: bool = True,
        func_name: str = "accelerated_loop",
        contract: Optional[Any] = None,
        scope_env: Optional[Dict[str, Any]] = None
    ) -> str:
        summary = cls.lift_c_loop(c_code, contract=contract, scope_env=scope_env)
        n_var_name = str(summary.iterations) if summary.iterations is not None else (summary.symbolic_iterations or "N")
        if in_place:
            return CodeGenerator.to_c_statements(summary, N_var=n_var_name)
        param_n = summary.symbolic_iterations or "N"
        return CodeGenerator.to_c_code(summary, func_name=func_name, N_var=param_n, preserve_names=True)

    @classmethod
    def accelerate_c_source(cls, c_source: str) -> str:
        """
        Scans a C source code string or file for `#pragma strilight accelerate` directives,
        lifts the subsequent iterative for-loop into an O(1) or O(log N) closed-form kernel,
        and replaces the pragma and loop block in-place with the synthesized C statements.
        """
        return process_c_pragmas(
            c_source=c_source,
            lift_c_loop_fn=cls.lift_c_loop,
            codegen_cls=CodeGenerator
        )

    @classmethod
    def _extract_c_for_block(cls, text: str) -> Tuple[str, int]:
        return extract_c_for_block(text)


def accelerate(fn: Optional[Callable] = None, *, guarded: bool = True) -> Callable:
    """
    Decorator that automatically detects and lifts iterative loops inside a Python function
    into an O(1) or O(log N) closed-form execution kernel.

    Features:
        - Automatic multi-variable recurrence lifting (Rule 7)
        - Polynomial and multi-capsule block-diagonal decoupling (Rule 14)
        - Cross-file constant and symbol resolution (CrossFileResolver)
        - Automatic Central-Force & Planetary Orbit Happy-Path deduction (CentralForceOrbitMatcher & Rule 13)
        - Guarded Fast-Path with seamless fallback

    Usage:
        @accelerate
        def simulate(N, a, b, c, d):
            for _ in range(N):
                ...
    """
    if fn is None:
        return lambda actual_fn: accelerate(actual_fn, guarded=guarded)

    try:
        src = inspect.getsource(fn)
        clean_src = textwrap.dedent(src)
        tree = ast.parse(clean_src)

        fn_def = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn.__name__:
                fn_def = node
                break

        if fn_def is None:
            return fn

        # Remove decorators to prevent recursion
        fn_def.decorator_list = []

        # Find the loop node in function body
        loop_idx = -1
        loop_node = None
        for i, stmt in enumerate(fn_def.body):
            if isinstance(stmt, (ast.For, ast.While)):
                loop_idx = i
                loop_node = stmt
                break

        if loop_node is None:
            return fn

        # 1. Resolve cross-file imports and constants
        scope_env = dict(fn.__globals__)
        try:
            external_constants = CrossFileResolver.resolve_imports_for_function(fn)
            scope_env.update(external_constants)
        except Exception as e:
            logger.debug("Cross-file resolution skipped: %s", e)

        # 2. Lift the loop with scope awareness
        lifter = PythonLoopLifter(scope_env=scope_env)
        lifter._extract_scope_arrays(fn_def)
        summary = lifter.lift(ast.Module(body=[loop_node], type_ignores=[]))

        can_lift = (
            not getattr(summary, 'has_unsupported_ops', False)
            and (summary.var_exprs or getattr(summary, 'array_mutations', None) or (summary.coupling_matrix and not summary.coupling_matrix.is_identity()))
        )

        # 3. If standard affine lifting was prevented by non-linear gravity / central force,
        # automatically deduce the Happy-Path via CentralForceOrbitMatcher (Rule 13)
        if not can_lift:
            orbit_sys = CentralForceOrbitMatcher.synthesize_orbit_system(loop_node, scope_env)
            if orbit_sys is not None:
                summary.orbit_system = orbit_sys
                summary.has_unsupported_ops = False
                can_lift = True

        if not can_lift:
            return fn

        # 4. Generate in-place Python replacement statements
        n_var = str(summary.iterations) if summary.iterations is not None else (summary.symbolic_iterations or "N")
        py_stmts = CodeGenerator.to_python_statements(summary, N_var=n_var, in_place=True)
        replacement_nodes = ast.parse(py_stmts).body

        # 5. Splice the accelerated statements into the function body
        fn_def.body = fn_def.body[:loop_idx] + replacement_nodes + fn_def.body[loop_idx + 1:]

        mod_tree = ast.Module(body=[fn_def], type_ignores=[])
        ast.fix_missing_locations(mod_tree)
        compiled_code = compile(mod_tree, filename="<strilight_accelerated>", mode="exec")

        fn_globals = fn.__globals__
        # Inject standard mathematical runtime symbols into fn_globals if not present (Globals Injection)
        import math
        from fractions import Fraction
        fn_globals.setdefault("Fraction", Fraction)
        fn_globals.setdefault("math", math)
        if getattr(summary, 'orbit_system', None) is not None:
            fn_globals["_strilight_orbit_system"] = summary.orbit_system

        local_env: Dict[str, Any] = {}
        exec(compiled_code, fn_globals, local_env)

        accelerated_raw = local_env[fn.__name__]

        @functools.wraps(fn)
        def guarded_fn(*args, **kwargs):
            if guarded:
                try:
                    return accelerated_raw(*args, **kwargs)
                except Exception as run_err:
                    logger.warning("[accelerate] Runtime fallback triggered (%s), seamlessly executing original loop.", run_err)
                    return fn(*args, **kwargs)
            return accelerated_raw(*args, **kwargs)

        # Attach formal mathematical metadata & invariant contract (Reflection Level 2)
        setattr(guarded_fn, "_loop_summary", summary)
        setattr(guarded_fn, "_invariant_contract", summary.invariant_contract)
        return guarded_fn

    except Exception as e:
        logger.debug("Safe fallback triggered in accelerate: %s", e)
        return fn


def accelerate_c_source(c_source: str) -> str:
    """
    Top-level helper to scan C source code for `#pragma strilight accelerate` directives
    and replace iterative loops in-place with closed-form C statements.
    """
    return SourceLifter.accelerate_c_source(c_source)


__all__ = [
    "BaseLanguageLifter",
    "PythonLoopLifter",
    "CLoopLifter",
    "CForLoopVisitor",
    "SourceLifter",
    "accelerate",
    "accelerate_c_source",
]
