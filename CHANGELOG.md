# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-09-05

### Added

#### 1. Exact Rational Arithmetic over $\mathbb{Q}$ (`strilight.engine.vsa.models`)
* Implemented exact fractional arithmetic within `AffineExpr` using Python's `fractions.Fraction`, ensuring complete precision preservation without floating-point rounding drift.
* Added `AffineExpr.__truediv__` and `AffineExpr.__rsub__` supporting closed operations over the rational field $\mathbb{Q}$.
* Upgraded matrix exponentiation code generators in both C and Python backends:
  * In C code generation (`CodeGenerator.to_c_statements`): dynamically switches matrix type definitions and accumulators from integer (`uint32_t`) to double-precision (`double`) when non-integer coefficients or fractional strides are present.
  * In Python code generation (`CodeGenerator.to_python_statements`): emits `Fraction(n, d)` terms and preserves rational values without forced modular reductions.
* Introduced the **Globals Injection** pattern in `SourceLifter`: automatically binds required runtime dependencies (`Fraction`, `math`) into the compiled callable's global namespace, eliminating inline import overhead.

#### 2. Multi-Language Frontend & Automated Source Lifting (`strilight.frontend`)
* Modularized the frontend into an extensible adapter architecture with `BaseLanguageLifter`:
  * **Python Subsystem (`strilight.frontend.python`)**: Pure AST-based analyzer for Python `for` loops, range expressions, and multi-variable recurrence induction.
  * **C Subsystem (`strilight.frontend.c`)**: `pycparser`-based analyzer supporting C `for` loops, struct member dereferences (`body->pos.x`), and sequential affine assignments.
* Implemented the `@accelerate` function decorator for Python: performs AST inspection at definition time, extracts loop structures, synthesizes equivalent $O(1)$ or $O(\log N)$ recurrence closed forms, and replaces loop bodies in-place.
* Implemented `#pragma strilight accelerate` and `#pragma strilight fuse` directives in C:
  * Detects adjacent loops sharing identical iteration domains and fuses them into a single unified recurrence kernel.
* Implemented array slice mutation lifting: classifies constant fills (`arr[:N] = c`), linear progressions, and accumulative modifications, generating optimized native slice assignments or `memset` calls.
* Added `CrossFileResolver` (`strilight.frontend.resolver`): statically traces cross-module imports and extracts numerical constants across project boundaries without dynamic evaluation.
* Added `CentralForceOrbitMatcher` (`strilight.frontend.orbit_matcher`): provides automated detection and analytical carrier fitting for central force and orbital mechanics patterns.

#### 3. Algebraic State Tensor Capsules & Dimensional Reduction (`strilight.engine.vsa.models`)
* Implemented `CompositeTensorDescriptor`: decouples abstract vector state spaces from underlying memory representation.
* Implemented algebraic interface condensation via Schur reduction: projects high-dimensional state dynamics onto boundary interface variables, enabling exact $O(1)$ state reconstruction via back-substitution.
* Implemented `VariableCouplingMatrix.decompose_block_diagonal`: uses graph component analysis to partition large coupled multi-variable recurrence systems into independent sub-matrices.

#### 4. Spatiotemporal 2D Coordinate & Analytical Perturbation Models
* Implemented `SpatiotemporalCoordinate`: models two-dimensional execution coordinates $\langle k, \xi \rangle$ (iteration index, intra-iteration offset) with lexicographical ordering.
* Implemented `SpatiotemporalTickModel`: provides unified timing models resolving read-after-write dependencies across loop iterations.
* Implemented `OrbitPerturbationSystem`: decomposes complex trajectories into analytical carriers and discrete perturbation models with turn counters ($K_{\text{flip}}$) and secular drift formulation.

---

### Changed

* **Architectural Decoupling**:
  * Decoupled the pure mathematical core (`strilight.engine`) from hardware-specific and low-level dynamic emulation modules.
  * Relocated dynamic tracing, symbolic stack handling, and solver translation components into `strilight.extensions`, loading them lazily via PEP 562 (`__getattr__`) to prevent unnecessary import-time overhead.
  * Extracted instruction definitions, disassemblers, and machine register maps into `strilight.arch`.
* **Mathematical Core Generalization**:
  * Replaced register-bound IR abstractions with language-agnostic models: `RegisterLoopExpr` $\to$ `VariableLoopExpr`, and `RegisterCouplingMatrix` $\to$ `VariableCouplingMatrix`.
  * Unified `LoopSummary.var_exprs` as the centralized store for symbolic induction expressions.
* **Abstract Domains Modernization (`strilight.engine.domains`)**:
  * Consolidated `Interval`, `StridedInterval`, and `DisjointIntervalSet` under a unified domains package.
  * Enforced zero-stride ($\sigma = 0$) handling for singleton intervals to preserve pointer alignment in abstract address arithmetic.
* **Packaging and Distribution**:
  * Updated build specifications to focus on the core algebraic engine and frontend acceleration API.
  * Modernized package metadata, project description, and dependencies in `pyproject.toml` and `setup.py`.

---

### Fixed

* Fixed symbolic loop evaluation in `models.py`: ensured `LoopSummary.iterations` defaults to `None` instead of `0`, preventing unintended zero-iteration identity reductions.
* Fixed numeric truncation in `lifter.py`: resolved an issue where floating-point strides and constants were cast to integers (`int(0.5) == 0`); they are now preserved as exact `Fraction` instances.
* Fixed code generation for mixed-type matrices: prevented C compilers from truncating rational multipliers by generating appropriate floating-point type definitions (`double`).
* Fixed runtime execution in synthesized functions: eliminated potential `NameError` exceptions by injecting module references into execution globals before compiling.

---

### Performance & Verification

* **Recurrence Matrix Acceleration**: Accelerated $10^6$-iteration multi-variable linear recurrences from $O(N)$ to $O(\log N)$, achieving bit-exact numerical parity verified across GCC `-O2`/`-O3` and CPython runtimes.
* **Cyclic Array Lookup Summation**: Evaluated $10^6$-iteration cyclic array summation loops via `@accelerate`, replacing step-by-step iterations with $O(1)$ closed forms.
* **Test Coverage**: 252 unit and integration tests passing across engine models, abstract domains, code generation, and multi-language frontend lifters.
