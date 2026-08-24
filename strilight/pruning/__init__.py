"""
Strilight Pruning Subpackage
============================
Provides mathematical abstract domains, Strided Intervals in modular ring arithmetic,
Bézout GCD congruence, dual-mask reduced products, and disjoint set management.
"""

from strilight.pruning.interval import (
    Interval,
    StridedInterval,
    DisjointIntervalSet,
)

__all__ = [
    "Interval",
    "StridedInterval",
    "DisjointIntervalSet",
]
