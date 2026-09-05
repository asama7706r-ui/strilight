"""
Strilight Architecture Subsystem (strilight.arch)
==================================================
Hardware architectures, universal execution trace compression,
instruction abstractions, and architecture-specific execution dispatchers.
"""

from strilight.arch.instruction import Instruction
from strilight.arch.loop_compressor import LoopBlock, TraceCompressor
import strilight.arch.x86 as x86

__all__ = [
    "Instruction",
    "LoopBlock",
    "TraceCompressor",
    "x86",
]
