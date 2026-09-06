"""
Strilight Engine Subpackage (strilight.engine)
==============================================
Pure mathematical foundation: abstract interpretation domains, abstract state,
recurrence equation models, and SMT closed-form translation.
"""

from strilight.engine.abstract_state import AbstractState
import strilight.engine.domains as domains
import strilight.engine.vsa as vsa

__all__ = [
    "AbstractState",
    "domains",
    "vsa",
]
