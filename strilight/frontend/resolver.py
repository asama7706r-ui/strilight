"""
Cross-File Symbol and Constant Resolver (strilight.frontend.resolver)
===================================================================
Statically inspects import statements in Python AST, locates referenced local
modules/files, and extracts constant assignments and parameters into a consolidated
scope dictionary without executing arbitrary runtime code.
"""

import os
import ast
import inspect
import logging
from fractions import Fraction
from typing import Dict, Any, Optional, Callable, Set, List, Union

logger = logging.getLogger(__name__)


class CrossFileResolver:
    """
    Static analyzer for resolving imported constants and definitions across files.
    """

    @classmethod
    def _safe_eval_ast_expr(cls, node: ast.AST, env: Dict[str, Any]) -> Any:
        """Safely evaluates constant expressions like `4 * PI * PI` using literal AST evaluation."""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            elif node.id == "True":
                return True
            elif node.id == "False":
                return False
            elif node.id == "None":
                return None
            raise ValueError(f"Unknown name: {node.id}")
        elif isinstance(node, ast.UnaryOp):
            operand = cls._safe_eval_ast_expr(node.operand, env)
            if isinstance(node.op, ast.USub):
                return -operand
            elif isinstance(node.op, ast.UAdd):
                return +operand
        elif isinstance(node, ast.BinOp):
            left = cls._safe_eval_ast_expr(node.left, env)
            right = cls._safe_eval_ast_expr(node.right, env)
            if isinstance(node.op, ast.Add):
                res = left + right
                return int(res) if isinstance(res, Fraction) and res.denominator == 1 else res
            elif isinstance(node.op, ast.Sub):
                res = left - right
                return int(res) if isinstance(res, Fraction) and res.denominator == 1 else res
            elif isinstance(node.op, ast.Mult):
                res = left * right
                return int(res) if isinstance(res, Fraction) and res.denominator == 1 else res
            elif isinstance(node.op, ast.Div):
                if right == 0:
                    raise ZeroDivisionError("division by zero in static evaluation")
                try:
                    f_left = Fraction(str(left)) if isinstance(left, (float, int)) else Fraction(left)
                    f_right = Fraction(str(right)) if isinstance(right, (float, int)) else Fraction(right)
                    frac = f_left / f_right
                    return int(frac) if frac.denominator == 1 else frac
                except Exception:
                    return left / right
            elif isinstance(node.op, ast.FloorDiv):
                return left // right
            elif isinstance(node.op, ast.Pow):
                return left ** right
            elif isinstance(node.op, ast.Mod):
                return left % right
        elif isinstance(node, ast.List):
            return [cls._safe_eval_ast_expr(el, env) for el in node.elts]
        elif isinstance(node, ast.Tuple):
            return tuple(cls._safe_eval_ast_expr(el, env) for el in node.elts)
        elif isinstance(node, ast.Dict):
            return {
                cls._safe_eval_ast_expr(k, env): cls._safe_eval_ast_expr(v, env)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }
        raise ValueError(f"Unsupported AST node for static evaluation: {type(node).__name__}")

    @classmethod
    def extract_constants_from_ast(cls, tree: ast.AST) -> Dict[str, Any]:
        """Extracts top-level constant and literal assignments from an AST tree."""
        constants: Dict[str, Any] = {}
        for stmt in tree.body if hasattr(tree, "body") else []:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        try:
                            val = cls._safe_eval_ast_expr(stmt.value, constants)
                            constants[target.id] = val
                        except Exception as e:
                            logger.debug("Skipping complex assignment %s: %s", target.id, e)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
                try:
                    val = cls._safe_eval_ast_expr(stmt.value, constants)
                    constants[stmt.target.id] = val
                except Exception as e:
                    logger.debug("Skipping complex annotated assignment %s: %s", stmt.target.id, e)
        return constants

    @classmethod
    def resolve_constants_from_file(cls, filepath: str) -> Dict[str, Any]:
        """Parses a local Python file into an AST and extracts top-level constants."""
        if not os.path.exists(filepath):
            logger.debug("File not found for constant resolution: %s", filepath)
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=filepath)
            return cls.extract_constants_from_ast(tree)
        except Exception as e:
            logger.debug("Failed to parse constants from %s: %s", filepath, e)
            return {}

    @classmethod
    def resolve_constants_from_c_content(cls, c_text: str) -> Dict[str, Any]:
        """
        Extracts #define macros and const variable assignments from C source/header text,
        safely evaluating arithmetic expressions with dependency resolution.
        """
        import re
        constants: Dict[str, Any] = {}
        if not c_text:
            return constants

        # Strip multi-line and single-line comments
        cleaned = re.sub(r'/\*.*?\*/', '', c_text, flags=re.DOTALL)
        cleaned = re.sub(r'//[^\n]*', '', cleaned)

        # 1. Match #define MACRO_NAME EXPR
        define_pattern = re.compile(r'#define\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+([^\n\r]+)')
        for m in define_pattern.finditer(cleaned):
            name = m.group(1).strip()
            expr_str = m.group(2).strip()
            # Clean C suffixes (e.g. 1.0f, 5LL, 10UL)
            expr_clean = re.sub(r'(?<=\d)[fFlLuU]+\b', '', expr_str)
            try:
                node = ast.parse(expr_clean, mode='eval')
                val = cls._safe_eval_ast_expr(node.body, constants)
                constants[name] = val
            except Exception as e:
                logger.debug("Could not statically evaluate C #define %s = %s: %s", name, expr_str, e)

        # 2. Match const type NAME = EXPR;
        const_pattern = re.compile(
            r'\b(?:static\s+)?const\s+(?:double|float|int|long|uint32_t|int64_t|size_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);'
        )
        for m in const_pattern.finditer(cleaned):
            name = m.group(1).strip()
            expr_str = m.group(2).strip()
            expr_clean = re.sub(r'(?<=\d)[fFlLuU]+\b', '', expr_str)
            try:
                node = ast.parse(expr_clean, mode='eval')
                val = cls._safe_eval_ast_expr(node.body, constants)
                constants[name] = val
            except Exception as e:
                logger.debug("Could not statically evaluate C const %s = %s: %s", name, expr_str, e)

        return constants

    @classmethod
    def resolve_constants_from_c_file(cls, filepath: str, search_dirs: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Locates a C header or source file and extracts its constants.
        """
        candidates = [filepath]
        if search_dirs:
            for d in search_dirs:
                candidates.append(os.path.join(d, filepath))
        candidates.append(os.path.join(os.getcwd(), filepath))

        target_path = None
        for cand in candidates:
            if os.path.exists(cand):
                target_path = cand
                break

        if not target_path:
            logger.debug("C file not found for constant resolution: %s", filepath)
            return {}

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
            return cls.resolve_constants_from_c_content(content)
        except Exception as e:
            logger.debug("Failed to read C file %s: %s", target_path, e)
            return {}

    @classmethod
    def resolve_imports_for_function(cls, fn: Callable) -> Dict[str, Any]:
        """
        Inspects the module enclosing `fn`, follows local relative import statements,
        and resolves external constants from neighboring project files.
        """
        resolved: Dict[str, Any] = {}

        # 1. Inspect live function globals if present
        fn_globals = getattr(fn, "__globals__", {})
        for k, v in fn_globals.items():
            if isinstance(v, (int, float, Fraction, str, bool, list, tuple, dict)):
                resolved[k] = v

        # 2. Inspect source file to follow imports statically
        try:
            src_file = inspect.getsourcefile(fn)
            if not src_file or not os.path.exists(src_file):
                return resolved

            src_dir = os.path.dirname(os.path.abspath(src_file))
            with open(src_file, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=src_file)

            # Traverse import statements
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    module_parts = node.module.split(".")
                    # Check relative file candidates
                    candidates = [
                        os.path.join(src_dir, *module_parts) + ".py",
                        os.path.join(src_dir, *module_parts, "__init__.py"),
                        os.path.join(os.getcwd(), *module_parts) + ".py",
                        os.path.join(os.getcwd(), *module_parts, "__init__.py"),
                    ]
                    for cand in candidates:
                        if os.path.exists(cand):
                            file_constants = cls.resolve_constants_from_file(cand)
                            for alias in node.names:
                                if alias.name == "*":
                                    resolved.update(file_constants)
                                elif alias.name in file_constants:
                                    out_name = alias.asname or alias.name
                                    resolved[out_name] = file_constants[alias.name]
                            break
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        module_parts = alias.name.split(".")
                        cand = os.path.join(src_dir, *module_parts) + ".py"
                        if os.path.exists(cand):
                            file_constants = cls.resolve_constants_from_file(cand)
                            mod_name = alias.asname or alias.name
                            resolved[mod_name] = file_constants

        except Exception as e:
            logger.debug("Cross-file resolution encountered exception: %s", e)

        return resolved
