"""
Developer Contract Parser for C Pragmas (strilight.frontend.c.contract)
======================================================================
Parses OpenMP-style inline clauses from `#pragma strilight accelerate ...` directives.
Supported clauses:
    - target(name) / entities(name)
    - include("filepath") / file("filepath")
    - model(name)
    - contract(key=val, ...)
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Any


@dataclass
class CPragmaContract:
    """
    Structured representation of a developer contract attached to a C pragma.
    """
    target: Optional[str] = None
    include_file: Optional[str] = None
    model: Optional[str] = None
    extra_clauses: Dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return (
            self.target is None
            and self.include_file is None
            and self.model is None
            and not self.extra_clauses
        )


def parse_c_pragma_contract(clause_str: str) -> CPragmaContract:
    """
    Parses OpenMP-style parenthesized clauses and contract directives:
        e.g., target(bodies) include("solar.h") model(cascade)
        e.g., contract(target=bodies, include="solar.h")
    """
    contract = CPragmaContract()
    if not clause_str or not clause_str.strip():
        return contract

    clean = clause_str.strip()

    # 1. Check for contract(...) wrapper
    contract_match = re.search(r'\bcontract\s*\(([^)]*)\)', clean)
    if contract_match:
        inner = contract_match.group(1).strip()
        # Parse key=val or key:val inside contract
        for item in re.split(r'[,;]\s*', inner):
            if '=' in item:
                k, v = item.split('=', 1)
                k = k.strip().lower()
                v = v.strip().strip('"\'')
                if k in ("target", "entities"):
                    contract.target = v
                elif k in ("include", "file", "header"):
                    contract.include_file = v
                elif k in ("model", "rule"):
                    contract.model = v
                else:
                    contract.extra_clauses[k] = v

    # 2. Parse individual OpenMP-style clauses: name(val)
    clause_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)')
    for m in clause_pattern.finditer(clean):
        c_name = m.group(1).lower()
        c_val = m.group(2).strip().strip('"\'')
        if c_name == "contract":
            continue
        if c_name in ("target", "entities"):
            contract.target = c_val
        elif c_name in ("include", "file", "header"):
            contract.include_file = c_val
        elif c_name in ("model", "rule"):
            contract.model = c_val
        else:
            contract.extra_clauses[c_name] = c_val

    return contract
