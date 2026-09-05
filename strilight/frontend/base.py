"""
Base Language Lifter Specification (strilight.frontend.base)
============================================================
Defines the abstract interface for all language-specific source code lifters.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional, Dict
from strilight.engine.vsa.models import LoopSummary


class BaseLanguageLifter(ABC):
    """
    Abstract base class for all language-specific loop lifters.
    Every language adapter (Python, C, Rust, etc.) must implement `lift`.
    """

    @abstractmethod
    def lift(self, source_or_ast: Any) -> LoopSummary:
        """
        Parses and lifts source code or an AST of the target language
        into a canonical `LoopSummary` mathematical recurrence model.
        """
        pass
