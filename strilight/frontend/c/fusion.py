"""
Strilight C Loop Fusion & Pragma Processor (strilight.frontend.c.fusion)
========================================================================
Scans C source code for `#pragma strilight accelerate` and `#pragma strilight fuse`
directives, extracts C for-loops, performs multi-loop fusion, and synthesizes kernels.
"""

import re
import logging
from typing import Tuple, Callable, Any, Dict, Optional

logger = logging.getLogger(__name__)


def extract_c_for_block(text: str) -> Tuple[str, int]:
    """
    Extracts the full C for-loop from `for (...) { ... }` or `for (...) stmt;`.
    Returns (loop_code, consumed_length).
    """
    paren_depth = 0
    header_end = -1
    i = 0
    started_paren = False
    while i < len(text):
        ch = text[i]
        if ch == '(':
            paren_depth += 1
            started_paren = True
        elif ch == ')':
            paren_depth -= 1
            if started_paren and paren_depth == 0:
                header_end = i + 1
                break
        i += 1

    if header_end == -1:
        return "", 0

    idx = header_end
    while idx < len(text) and text[idx].isspace():
        idx += 1

    if idx >= len(text):
        return "", 0

    if text[idx] == '{':
        brace_depth = 0
        j = idx
        while j < len(text):
            if text[j] == '{':
                brace_depth += 1
            elif text[j] == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    return text[:j + 1], j + 1
            j += 1
        return "", 0
    else:
        semi_pos = text.find(';', idx)
        if semi_pos != -1:
            return text[:semi_pos + 1], semi_pos + 1
        return "", 0


def process_c_pragmas(
    c_source: str,
    lift_c_loop_fn: Callable[[str], Any],
    codegen_cls: Any
) -> str:
    """
    Scans a C source code string or file for `#pragma strilight accelerate` and `fuse` directives,
    lifts the subsequent iterative for-loop into an O(1) or O(log N) closed-form kernel,
    and replaces the pragma and loop block in-place with the synthesized C statements.
    """
    pragma_pattern = re.compile(r'#pragma\s+strilight\s+(accelerate|fuse)([^\n]*)', re.MULTILINE)
    matches = list(pragma_pattern.finditer(c_source))
    if not matches:
        return c_source

    output_parts = []
    last_pos = 0

    for match in matches:
        pragma_start = match.start()
        pragma_end = match.end()
        directive_kind = match.group(1)
        clause_tail = match.group(2)

        output_parts.append(c_source[last_pos:pragma_start])

        from strilight.frontend.c.contract import parse_c_pragma_contract
        from strilight.frontend.resolver import CrossFileResolver

        contract = parse_c_pragma_contract(clause_tail)
        scope_env: Dict[str, Any] = {}
        if contract.include_file:
            scope_env = CrossFileResolver.resolve_constants_from_c_file(contract.include_file)

        remaining = c_source[pragma_end:]
        for_match = re.search(r'\b(for|while)\s*\(', remaining)
        if not for_match:
            output_parts.append(c_source[pragma_start:pragma_end])
            last_pos = pragma_end
            continue

        for_start_in_rem = for_match.start()
        between_text = remaining[:for_start_in_rem]

        full_loop_code, loop_end_in_rem = extract_c_for_block(remaining[for_start_in_rem:])
        if not full_loop_code:
            output_parts.append(c_source[pragma_start:pragma_end])
            last_pos = pragma_end
            continue

        consumed_total = for_start_in_rem + loop_end_in_rem
        merged_loop_code = full_loop_code
        is_fused = False

        if directive_kind == "fuse":
            rem_after_first = remaining[consumed_total:]
            next_for = re.search(r'^\s*(/\*.*?\*/|//[^\n]*\n|\s*)*(for|while)\s*\(', rem_after_first)
            if next_for:
                m_kw = re.search(r'\b(for|while)\b', rem_after_first)
                next_for_start = m_kw.start() if m_kw else 0
                second_loop_code, second_len = extract_c_for_block(rem_after_first[next_for_start:])
                if second_loop_code:
                    first_brace = full_loop_code.find('{')
                    second_brace = second_loop_code.find('{')
                    if first_brace != -1 and second_brace != -1:
                        header = full_loop_code[:first_brace].strip()
                        body1 = full_loop_code[first_brace+1:full_loop_code.rfind('}')].strip()
                        body2 = second_loop_code[second_brace+1:second_loop_code.rfind('}')].strip()
                        merged_loop_code = f"{header} {{\n    {body1}\n    {body2}\n}}"
                        consumed_total += next_for_start + second_len
                        is_fused = True

        actual_loop_end = pragma_end + consumed_total

        try:
            import inspect
            sig = inspect.signature(lift_c_loop_fn)
            kwargs = {}
            if "contract" in sig.parameters:
                kwargs["contract"] = contract
            if "scope_env" in sig.parameters:
                kwargs["scope_env"] = scope_env

            summary = lift_c_loop_fn(merged_loop_code, **kwargs)
            has_orbit = getattr(summary, 'orbit_system', None) is not None
            if (
                getattr(summary, 'has_unsupported_ops', False)
                or (
                    not summary.var_exprs
                    and not getattr(summary, 'array_mutations', None)
                    and (not summary.coupling_matrix or summary.coupling_matrix.is_identity())
                )
            ) and not has_orbit:
                output_parts.append(between_text + "/* [strilight] Graceful fallback: non-linear loop preserved */\n" + merged_loop_code)
            else:
                n_var_name = str(summary.iterations) if summary.iterations is not None else (summary.symbolic_iterations or "N")
                fast_c = codegen_cls.to_c_statements(summary, N_var=n_var_name)
                tag = "Contract Accelerated" if not contract.is_empty() else ("Fused Accelerated" if is_fused else "Accelerated")
                output_parts.append(between_text + f"/* [strilight] {tag} O(1)/O(log N) kernel */\n{{\n    {fast_c}\n}}")
        except Exception as e:
            logger.warning("[process_c_pragmas] Fallback due to: %s", e)
            output_parts.append(between_text + merged_loop_code)

        last_pos = actual_loop_end

    output_parts.append(c_source[last_pos:])
    return "".join(output_parts)
