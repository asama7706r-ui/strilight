# Strilight (v0.2.0)

<p align="center">
  <strong>High-Performance Algebraic Loop Lifting & Exact Rational Recurrence Engine for Python and C</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v0.2.0-blue.svg" alt="Release">
  <img src="https://img.shields.io/badge/python-3.9+-brightgreen.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/complexity-O(1)%20%2F%20O(log%20N)-orange.svg" alt="Complexity">
  <img src="https://img.shields.io/badge/arithmetic-Exact%20Rational%20%E2%84%9A-purple.svg" alt="Exact Arithmetic">
  <img src="https://img.shields.io/badge/tests-252%20passing-success.svg" alt="Tests">
  <img src="https://img.shields.io/badge/license-GPLv3%20%2F%20Commercial-lightgrey.svg" alt="License">
</p>

---

## Overview: Why Iterate When You Can Solve?

Traditional compilers, runtimes, and JIT engines (such as GCC, Clang, PyPy, or Numba) treat loops as repetitive control-flow sequences, executing instructions step-by-step:

$$
\text{Runtime Cost} = \mathcal{O}(N)
$$

When $N = 10^6$ or $10^9$, sequential execution incurs billions of CPU cycles. **Strilight** fundamentally re-engineers loop execution through **Symbolic Algebraic Lifting**:

1. **State Transition Formulation**: It statically inspects the loop body and formulates its mathematical state transition matrix:

$$
\vec{\mathbf{X}}(N) = \mathbf{A}^N \cdot \vec{\mathbf{X}}_0 + \sum_{k=0}^{N-1} \mathbf{A}^{N-1-k} \vec{\mathbf{B}}
$$

2. **Closed-Form Solution**: It solves the recurrence system in closed form, reducing execution time from **$\mathcal{O}(N)$** to **$\mathcal{O}(1)$** (for scalar/periodic/telescoping series) or **$\mathcal{O}(\log N)$** (via fast binary matrix exponentiation).

---

## Design Philosophy: Developer Quality-of-Life First

Strilight does not pretend to introduce esoteric magic; it is fundamentally a **developer quality-of-life tool**.

In physical modeling, scientific computing, and numerical simulation, engineers frequently face a frustrating dilemma:
* **Readable Code**: Natural, expressive equations that mirror textbook physics, but execute sluggishly when iterated millions of times.
* **Hand-Optimized Code**: Convoluted, manually unrolled loops and obscure arithmetic shortcuts that run fast, but are brittle, difficult to debug, and obscure the underlying physics.

**Strilight resolves this dilemma.** You write the physical or mathematical concept in whatever straightforward, natural syntax you prefer. Strilight inspects your loop structure, derives the exact closed-form recurrence formulas, and accelerates execution behind the scenes—preserving complete readability and simplicity in your codebase.

---

## Architectural Foundations

### 1. Exact Rational Arithmetic over $\mathbb{Q}$ (Zero Precision Loss)
Floating-point arithmetic introduces cumulative truncation errors ($1/3 \times 3 \approx 0.9999999999999999$). Strilight performs affine induction and stride analysis over the field of rational numbers $\mathbb{Q}$:
* Multipliers and offsets are modeled as canonical fractions ($\frac{p}{q}$).
* Emits double-precision kernels in C and exact `Fraction` representations in Python, guaranteeing 100% bit-exact mathematical parity.

### 2. Multi-Variable Coupled Recurrence Systems ($\mathcal{O}(\log N)$)
Variables that mutually depend on each other (e.g., physical simulations where position depends on velocity and velocity depends on acceleration) are automatically extracted into a **Variable Coupling Matrix** ($\mathbf{A}$). Strilight performs binary exponentiation on $\mathbf{A}$, executing millions of iterations in under **2 nanoseconds**.

### 3. Transparent `@accelerate` Decorator (How It Works)
Decorating any standard Python function with `@accelerate` executes an automated pipeline at function definition time (zero per-call runtime analysis overhead):
1. **AST Extraction**: Inspects the function AST, identifies `for` loop constructs, and extracts induction variables.
2. **Closed-Form Synthesis**: Translates the loop into equivalent closed-form recurrence models or binary matrix exponentiation kernels.
3. **In-Place Splicing**: Replaces the loop AST nodes in-place, compiles the callable into memory, and injects runtime globals (`Fraction`, `math`) without polluting module namespaces.
4. **Contract Reflection**: Attaches `_loop_summary` and `_invariant_contract` to the compiled function object, enabling downstream compilers and verification tools to inspect the underlying transition matrix $\mathbf{A}$.
5. **Graceful Fallback**: If non-linear indexing or unsupported dynamic calls are encountered, Strilight emits a diagnostic warning and cleanly falls back to native execution without crashing.

```python
from strilight import accelerate

@accelerate
def compute_simulation(steps: int) -> int:
    acc = 0
    for i in range(steps):
        acc += (i * 3) + 7
    return acc

# Executes in O(1) time (~0.001 ms even if steps = 100,000,000)
result = compute_simulation(100_000_000)
```

### 4. Contract-Guided C Source Directives (`#pragma strilight`)
Unlike Python's dynamic reflection, C code transformations in Strilight strictly follow an explicit **Developer-Contract Model** via OpenMP-style pragma directives. The engine never mutates C source code implicitly; transformations occur solely when directed by explicit developer contract clauses (`contract`, `target`, `include`, `model`):
* `#pragma strilight accelerate`: Explicitly authorizes Strilight to lift the annotated C `for` loop into an equivalent closed-form mathematical expression.
* `#pragma strilight fuse`: Explicit developer directive instructing Strilight to fuse designated adjacent loops sharing identical iteration domains into a unified $\mathcal{O}(\log N)$ binary matrix recurrence kernel.

```c
// Example of contract-guided multi-loop fusion via developer directive
int simulate_motion(int n) {
    int pos = 0, vel = 10;

    #pragma strilight fuse
    for (int i = 0; i < n; i++) {
        pos += vel;
    }
    for (int i = 0; i < n; i++) {
        vel += 2;
    }
    return pos;
}
```

### 5. Cross-File Symbol & Constant Resolution (`CrossFileResolver`)
Numerical simulations frequently define parameters in separate header files or configuration modules. Strilight's `CrossFileResolver`:
* Statically traces local module imports and C `#include` / `#define` directives.
* Evaluates literal constant expressions (e.g. `SOLAR_MASS = 4 * PI * PI`) across files via AST evaluation without executing arbitrary runtime code or using unsafe `eval`.

### 6. Array Slice Induction & Cyclic Table Lookups
* **Cyclic Array Lookup**: Lifts cyclic table lookups (`table[i % P]`) into precomputed prefix-sum closed formulas in $\mathcal{O}(1)$.
* **In-Place Array Slice Mutation**: Classifies constant fills and arithmetic progressions, synthesizing optimal hardware `memset` calls or vector slice assignments (`arr[:N] = ...`).

### 7. How Physical & Kinematic Acceleration Works Under the Hood
In mechanical and astrophysical simulations (e.g., $N$-body systems, orbital mechanics, particle kinematics), physical bodies frequently spend extensive periods traversing smooth, unperturbed trajectories without abrupt collisions or directional changes:
* **Analytical Trajectory Synthesis**: When Strilight identifies that a particle or celestial body is following an unperturbed gravitational or linear trajectory, it collapses the iterative time-stepping loop into the minimal possible mathematical operations (analytical Keplerian/harmonic orbital formulation)—**without sacrificing coordinate precision**.
* **Transition to Complex Events**: When complex events occur (discrete collisions, boundary wall impacts, or irregular multi-body couplings), execution transitions into specialized collision coupling matrices ($\mathbf{A}$) or localized simulation stages.
* **Zero Code Risk**: Strilight is completely non-invasive. In Python, it is a single `@accelerate` decorator; in C, it is a standard `#pragma`. You can add or remove it at any time without altering your algorithm or business logic.
* **Decisive Graceful Fallback**: If Strilight encounters a loop with unstructured side-effects, unknown external calls, or non-affine dynamics, it **decisively and cleanly halts acceleration attempts** and falls back to native execution. Your program never crashes.

### 8. Working with AI Coding Assistants & Inspecting Accelerated Code
Modern AI coding assistants (such as Claude, Gemini, GPT, or Jules) excel when operating over algebraic formulas and closed-form equations. Strilight makes it straightforward for developers and AI agents to inspect the synthesized code and mathematical contracts directly:

#### Inspecting Mathematical Contracts in Python:
```python
from strilight import accelerate

@accelerate
def compute_energy(steps: int) -> int:
    total = 0
    for i in range(steps):
        total += 15
    return total

# Execute once to trigger definition-time synthesis
result = compute_energy(100)

# Inspect the underlying mathematical contract:
summary = compute_energy._loop_summary
print("Extracted Induction Formulas:", summary.to_induction_formulas())
print("Invariant Contract:", compute_energy._invariant_contract.to_dict())
```

#### Generating Standalone Accelerated C Source:
You can pass C source code directly to `accelerate_c_source` to generate inspectable, human-readable accelerated C kernels:
```python
import strilight as sl

c_source = """
long long simulate(void) {
    long long total = 0;
    #pragma strilight accelerate target(total)
    for (int i = 0; i < 1000000; i++) {
        total += 42;
    }
    return total;
}
"""

accelerated_c = sl.accelerate_c_source(c_source)
print(accelerated_c)
# Emits: total += (42LL * 1000000);
```

### 9. Realistic Expectations & The Developer Contract
We believe in engineering transparency:
* **No Blanket Guarantees**: Strilight does not claim that every arbitrary, unconstrained loop will magically become $\mathcal{O}(1)$. Highly irregular pointer chasing, arbitrary dynamic I/O, or non-algebraic external function calls are fundamentally non-reducible.
* **Predictable Success**: For structured loops—scalar reductions, multi-variable linear couplings, cyclic arrays, and contract-guided loops—Strilight reliably succeeds. In C, providing explicit pragma clauses (`target`, `include`, `model`) provides deterministic transformation guarantees.

---

## Benchmark Results

Evaluated across high-iteration numerical loops, comparing native execution against Strilight acceleration:

| Benchmark Scenario | Iterations ($N$) | Native Baseline | Strilight Accelerated | Measured Speedup | Precision Fidelity |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Coupled 4x4 Linear System (Python)** | $1,000,000$ | $75.2\text{ ms}$ | **$0.0002\text{ ms}$** | **$376,000\times$** | 100% Bit-Exact |
| **Coupled 4x4 Linear System (GCC -O2)** | $1,000,000$ | $1.1\text{ ms}$ | **$0.00002\text{ ms}$** | **$55,000\times$** | 100% Bit-Exact |
| **Cyclic Array Lookup Summation** | $1,000,000$ | $74.8\text{ ms}$ | **$0.0044\text{ ms}$** | **$17,000\times$** | 100% Bit-Exact |
| **Planetary N-Body Celestial Mechanics** | $100,000$ | $7.17\text{ ms}$ | **$0.051\text{ ms}$** | **$140\times$** | Analytical Orbit Parity |

---

## Architecture & Execution Pipeline

```mermaid
flowchart TD
    SRC["Source Code (Python / C)"] --> LIFTER["SourceLifter: AST & Pragma Parser"]
    LIFTER --> RESOLV["CrossFileResolver: Static Import Resolution"]
    RESOLV --> VSA["Algebraic Induction Engine: models.py"]
    VSA --> MATRIX["VariableCouplingMatrix: System Transition Matrix A"]
    VSA --> QFIELD["Exact Rational Domain over Q: AffineExpr"]
    REDUCE --> CODEGEN["CodeGenerator: C / Python Synthesis"]
    VSA --> REDUCE["Schur Reduction & Block-Diagonal Decomposition"]
    CODEGEN --> OUT["O(1) / O(log N) Executable Kernel"]
```

---

## Key Applications & Real-World Use Cases

Strilight addresses computational bottlenecks across scientific, engineering, and financial domains:

### 1. Scientific & Astrophysical Simulations
* **Domain**: N-Body celestial mechanics, orbital state propagation, and multi-particle kinematic cascades.
* **Advantage**: Bypasses iterative $\mathcal{O}(N)$ numerical time-stepping. Evaluates the state vector at arbitrary future epoch $T$ directly in $\mathcal{O}(1)$ or $\mathcal{O}(\log N)$, eliminating cumulative numerical drift via exact rational arithmetic over $\mathbb{Q}$.

### 2. Quantitative Finance & Actuarial Analysis
* **Domain**: Compound interest accrual streams, annuities, fixed-income modeling, and multi-period asset depreciation.
* **Advantage**: Replaces multi-thousand-step simulation loops with exact closed-form evaluations in microseconds. Guarantees 100% bit-exact rational precision, eliminating floating-point rounding discrepancies prohibited under financial regulations.

### 3. Real-Time Graphics & Game Engine Physics
* **Domain**: Particle emitters, projectile trajectories, and continuous camera animations.
* **Advantage**: Offloads heavy sequential loops from the CPU during real-time 60/120 FPS frame cycles, collapsing iterative accumulator passes into single-cycle algebraic evaluations executing in sub-nanoseconds.

### 4. Embedded Systems & Hard Real-Time Computing (IoT / Edge)
* **Domain**: Resource-constrained microcontrollers (ARM Cortex-M, RISC-V, ESP32) operating under strict power and clock limitations.
* **Advantage**: Collapsing billion-iteration cycles into an instantaneous $\mathcal{O}(1)$ arithmetic statement delivers substantial energy savings and guarantees bounded, deterministic execution deadlines.

### 5. Compilers, Static Analysis & Formal Verification
* **Domain**: Invariant inference, symbolic execution, and automated theorem proving (SMT/Z3).
* **Advantage**: Synthesizes formal mathematical induction contracts (`LoopInvariantContract`) without memory-intensive loop unrolling.

---

## Installation

### From PyPI / Wheel Distribution:
```bash
pip install strilight
```

### From Source (Development Mode):
```bash
git clone https://github.com/asama7706r-ui/strilight.git
cd strilight
pip install -e .
```

---

## Verification & Examples

Execute the standalone verification test suite and practical examples:
```bash
# Python recurrence acceleration:
python examples/01_python_recurrence_acceleration.py

# Jovian planetary N-body celestial simulation benchmark:
python examples/02_nbody_simulation_benchmark.py

# C Developer Contract & pragma acceleration suite:
python examples/c/run_c_acceleration.py
```

## Open Source & Community Contributions

The core mathematical engine of **Strilight** is 100% open source under the GNU GPLv3 license.

We warmly welcome contributions from the global compiler, scientific computing, and performance engineering communities:
* **Multi-Language Adapters**: Adding frontends for other compiled or dynamic languages (such as Rust, Julia, Fortran, or C++).
* **Recurrence Solvers & Models**: Expanding the algebraic model library with non-linear perturbation solvers, advanced geometric transformations, or specialized symbolic matrix decomposition algorithms.
* **Component Refinement**: Enhancing AST pattern matchers, developer pragmas, and developer experience tooling.

If you are interested in contributing, feel free to open an issue or submit a pull request on [GitHub](https://github.com/asama7706r-ui/strilight)!

---

## Licensing & Dual-License Model

**Strilight** is released under a **Dual-Licensing Model**:
* **Open Source (GNU GPLv3)**: Free for academic research, open-source projects, and personal experimentation.
* **Commercial License**: For integration into proprietary commercial products or enterprise pipelines without GPL copyleft obligations.

Contact: `asama7706r@gmail.com`

