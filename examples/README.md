# Strilight Examples & Quickstart Directory

This directory contains practical, standalone examples demonstrating how to use **Strilight** for algebraic loop acceleration, developer contracts, and invariant synthesis in both Python and C.

---

## Catalog of Examples

### 1. Python Loop Acceleration
- [`01_python_recurrence_acceleration.py`](./01_python_recurrence_acceleration.py)
  - **Focus**: Transparent `@sl.accelerate` decorator on affine loop recurrences.
  - **Demonstrates**:
    - Transforming an $O(N)$ loop (100,000,000 iterations) into a $1.6\,\mu\text{s}$ $O(1)$ closed form.
    - Inspecting the generated `LoopInvariantContract` attached to the accelerated function for formal verification.

- [`02_nbody_simulation_benchmark.py`](./02_nbody_simulation_benchmark.py)
  - **Focus**: Real-world scientific computing benchmark based on the canonical Debian Computer Language Benchmarks Game (symplectic Jovian N-body integrator).
  - **Demonstrates**: Transparent acceleration safety fallback on non-linear systems.

---

### 2. C Language Developer Contracts (`examples/c/`)
A dedicated directory showing how to guide static C loop lifting and code synthesis using OpenMP-style pragmas:

- [`examples/c/README.md`](./c/README.md): Comprehensive reference on contract syntax, clauses (`target`, `include`, `model`), and static cross-file header analysis.
- [`examples/c/01_scalar_reduction/`](./c/01_scalar_reduction/):
  - `scalar_kernel.c`: `#pragma strilight accelerate target(total) include("config.h") model(linear)`
  - `config.h`: Static `#define` macros resolved without executing code.
- [`examples/c/02_array_mutation/`](./c/02_array_mutation/):
  - `array_kernel.c`: In-place array mutation kernel with contract.
- [`examples/c/03_loop_fusion/`](./c/03_loop_fusion/):
  - `fusion_kernel.c`: Combining back-to-back loops using `#pragma strilight fuse target(...)`.
- [`examples/c/run_c_acceleration.py`](./c/run_c_acceleration.py):
  - Runnable script demonstrating the before-and-after transformation of C code directly in the terminal.

---

## How to Run

### Run Python Recurrence Example:
```bash
python examples/01_python_recurrence_acceleration.py
```

### Run N-Body Simulation Benchmark:
```bash
python examples/02_nbody_simulation_benchmark.py
```

### Run C Developer Contract Demonstration:
```bash
python examples/c/run_c_acceleration.py
```
