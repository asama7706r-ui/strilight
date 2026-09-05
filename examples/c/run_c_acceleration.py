#!/usr/bin/env python3
"""
Strilight C Developer Contract Acceleration Runner
==================================================
This educational script demonstrates how Strilight parses OpenMP-style Developer
Contracts directly from C source code files, resolves constants across separate
C header files, and synthesizes O(1)/O(log N) closed-form execution kernels.

Usage:
    python run_c_acceleration.py
"""

import os
import sys

# Ensure repository root is in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import strilight as sl


def display_transformation(title: str, c_filepath: str):
    print("=" * 78)
    print(f"  {title}")
    print(f"  File: {os.path.relpath(c_filepath, REPO_ROOT)}")
    print("=" * 78)

    with open(c_filepath, "r", encoding="utf-8") as f:
        original_c = f.read()

    print("\n--- [Original C Source with Developer Contract] ---")
    print(original_c.strip())

    # Accelerate the C source code via Strilight
    accelerated_c = sl.accelerate_c_source(original_c)

    print("\n--- [Accelerated Closed-Form C Output] ---")
    print(accelerated_c.strip())
    print("\n")


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Scalar Reduction with Header Resolution
    scalar_file = os.path.join(base_dir, "01_scalar_reduction", "scalar_kernel.c")
    display_transformation(
        "1. Scalar Reduction Kernel (O(N) -> O(1) via Contract & Header Resolution)",
        scalar_file
    )

    # 2. In-Place Array Mutation
    array_file = os.path.join(base_dir, "02_array_mutation", "array_kernel.c")
    display_transformation(
        "2. In-Place Array Mutation Kernel (Developer Contract Driven)",
        array_file
    )

    # 3. Loop Fusion
    fusion_file = os.path.join(base_dir, "03_loop_fusion", "fusion_kernel.c")
    display_transformation(
        "3. Loop Fusion Directive (Two Sequential Loops Fused & Accelerated)",
        fusion_file
    )


if __name__ == "__main__":
    main()
