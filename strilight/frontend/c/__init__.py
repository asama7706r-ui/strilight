"""
Strilight C Frontend Package
============================
Exposes C-specific AST loop lifters, pragma processors, and fusion algorithms.
"""

from strilight.frontend.c.lifter import CLoopLifter, CForLoopVisitor
from strilight.frontend.c.fusion import extract_c_for_block, process_c_pragmas

__all__ = [
    "CLoopLifter",
    "CForLoopVisitor",
    "extract_c_for_block",
    "process_c_pragmas",
]
