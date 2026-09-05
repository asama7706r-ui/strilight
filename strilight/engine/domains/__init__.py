"""
Strilight Mathematical Abstract Domains (strilight.engine.domains)
==================================================================
Modular ring arithmetic intervals, Strided Intervals, Bézout GCD congruence,
dual-mask reduced products, and disjoint set management for VSA.
"""

from strilight.engine.domains.interval import (
    Interval,
    StridedInterval,
    DisjointIntervalSet,
)

__all__ = [
    "Interval",
    "StridedInterval",
    "DisjointIntervalSet",
]
