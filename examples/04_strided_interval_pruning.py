"""
Example 04: Strided Interval Domain & Modulo Congruence Aliasing Pruning
Demonstrates circular intervals, Bézout GCD arithmetic, dual-mask reduced products,
and instant memory aliasing disjointness proofs.
"""

import os
import sys

# Auto-inject project root into sys.path for standalone execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from strilight.pruning.interval import StridedInterval, DisjointIntervalSet


def main():
    print("=" * 60)
    print("  [Strilight] Example 04: Strided Intervals & Modulo Pruning")
    print("=" * 60)

    # 1. Create two strided intervals representing heap access pointers:
    # Array A: elements at index 4*i + 0 -> Stride 4, offset 0 in [0x1000, 0x1400]
    # Array B: elements at index 4*j + 2 -> Stride 4, offset 2 in [0x1002, 0x1402]
    ptr_a = StridedInterval(min_val=0x1000, max_val=0x1400, stride=4)
    ptr_b = StridedInterval(min_val=0x1002, max_val=0x1402, stride=4)

    print("\n[Step 1] Strided Interval Representations:")
    print(f"  Pointer A : {ptr_a}")
    print(f"  Pointer B : {ptr_b}")

    # 2. Test for Modulo Congruence Disjointness:
    is_disjoint = ptr_a.is_disjoint_modulo(ptr_b)
    print(f"\n[Step 2] Instant Modulo Congruence Aliasing Test:")
    print(f"  -> Are Pointer A and Pointer B 100% Disjoint? : {is_disjoint}")
    print(f"  -> Reason: gcd(4, 4) = 4, and (0x1000 mod 4) != (0x1002 mod 4).")

    # 3. Dual-Mask 3-Valued Logic Reduction:
    # StridedInterval automatically deduces fixed bits from strides:
    print(f"\n[Step 3] Dual-Mask Reduced Product Deduction:")
    print(f"  Pointer A Known Bitmask : {hex(ptr_a.known_mask)}")
    print(f"  Pointer A Known Value   : {hex(ptr_a.known_value)}")

    # 4. DisjointIntervalSet with K-Limit Convex Hull:
    print(f"\n[Step 4] Managing Disjoint Interval Sets with K-Limit:")
    disjoint_set = DisjointIntervalSet(k_limit=3)
    disjoint_set.add(StridedInterval(0x10, 0x20, stride=2))
    disjoint_set.add(StridedInterval(0x30, 0x40, stride=2))
    disjoint_set.add(StridedInterval(0x50, 0x60, stride=2))
    print(f"  Disjoint Set Count (<= K): {len(disjoint_set.intervals)} intervals")

    # Adding a 4th triggers automatic convex hull merge to prevent state explosion:
    disjoint_set.add(StridedInterval(0x70, 0x80, stride=2))
    print(f"  Disjoint Set after K-Limit merge: {len(disjoint_set.intervals)} interval: {disjoint_set.intervals[0]}")


if __name__ == "__main__":
    main()
