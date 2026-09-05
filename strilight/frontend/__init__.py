"""
Strilight Frontend Subsystem (strilight.frontend)
==================================================
Modular language AST lifters, transparent function decorators, and multi-language
code generators (Python and C/C++) for O(1) / O(log N) loop acceleration.
"""

from strilight.frontend.base import BaseLanguageLifter
from strilight.frontend.codegen import CodeGenerator
from strilight.frontend.source_lifter import (
    SourceLifter,
    PythonLoopLifter,
    CLoopLifter,
    accelerate,
    accelerate_c_source,
)

__all__ = [
    "BaseLanguageLifter",
    "CodeGenerator",
    "SourceLifter",
    "PythonLoopLifter",
    "CLoopLifter",
    "accelerate",
    "accelerate_c_source",
]
