# 📋 Strilight Changelog

All notable architectural enhancements, new subsystems, optimizations, and bug fixes in **Strilight** comparing the **development repository (`ousama` / `origin/main`)** against the **public release repository (`strilight` / `public/main`)**.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 🚀 [v0.1.0-alpha.2] - 2026-08-27

### 🧠 1. Modular VSA Subsystem Architecture (`strilight.engine.vsa`)
The monolithic `vsa_evaluator.py` engine was completely refactored and decomposed into a modular, high-performance subpackage (`strilight.engine.vsa`) while preserving 100% backward compatibility:

* **`strilight/engine/vsa/models.py` [NEW]**:
  * Formalized **The Grand Master Recurrence Equation**:
    $$X(N) = \mathbf{A}(N) \cdot X_0 + \mathbf{\Delta}(N)$$
  * **Multiplicative Scale Kernels $\mathbf{A}(N)$**:
    * `ScaleKernel` (Base interface).
    * `IdentityScale`: Linear additive recurrence ($A(N) = 1$).
    * `GeometricScale`: Exponential scaling ($A(N) = 2^N$ or $S^N$).
    * `PolynomialCascade`: High-order polynomial transformations.
  * **Additive Delta Kernels $\mathbf{\Delta}(N)$**:
    * `DeltaKernel` (Base interface).
    * `ZeroDelta`: Invariant state preservation ($\Delta(N) = 0$).
    * `AffineStride`: Uniform linear progression ($\Delta(N) = N \cdot \text{step}$).
    * `PolycyclicPattern`: Quotient-remainder closed-form modulo cycles:
      $$\Delta(N) = \lfloor \frac{N}{P} \rfloor \cdot \sum_{i=0}^{P-1} x_i + \text{PrefixSum}(N \bmod P)$$
    * `TelescopingCascade`: Multi-variable telescoping recurrence solver.
    * `CompoundKernel`: Composition of multiple algebraic kernels.
  * **Core Representation Structures**:
    * `RegisterLoopExpr`: Unified wrapper combining $A(N)$ and $\Delta(N)$ for registers and memory.
    * `LoopSummary`: Added `direct_records`, `inner_loop_summaries`, `constant_sets`, `loop_expressions`, and `exit_records`.
    * `LoopInvariantContract`: AST boundary substitution enforcing the $N-1$ iron invariant.
* **`strilight/engine/vsa/evaluator.py` [NEW]**:
  * Pure data-flow abstract interpretation engine (`LoopEvaluator`).
  * Fixpoint iteration with widening/narrowing on Strided Interval domains.
  * Nested loop evaluation and recursive composition of inner loop deltas.
  * Direct non-loop instruction capture (`direct_records`) for scope transition prologues.
  * Pluggable dynamic `memory_provider` binding.
* **`strilight/engine/vsa/smt_translator.py` [NEW]**:
  * Fully decoupled SMT-LIB2 / Z3 BitVector constraint compilation (`LoopSMTTranslator`).
  * `build_loop_exit_constraints`: Compiles loop exit conditions in $O(1)$ directly to Z3 ASTs.
  * `translate_loop_summary_to_smt_updates`: Transforms loop summaries into concrete SSA BitVector updates.
  * `eval_target_at_step`: Evaluates target expressions against concrete memory addresses from exit records.
* **`strilight/engine/vsa/dispatcher.py` [NEW]**:
  * Centralized instruction semantics dispatcher handling x86-64 ALU operations, bitwise arithmetic, and control flow.
* **`strilight/engine/vsa/state_ops.py` [NEW]**:
  * Abstract machine state transformer (`AbstractState`), Join ($\sqcup$) and Meet ($\sqcap$) lattice operations, and StridedInterval equality checks.
* **`strilight/engine/vsa/symbolic.py` [NEW]**:
  * `SymbolicInductionAnalyzer`: Dynamic extraction of periodic table lookups and complex cyclic state changes from instruction traces.
* **`strilight/engine/vsa_evaluator.py` [REFACTOR]**:
  * Re-architected as a lightweight backward-compatible facade delegating all calls to `strilight.engine.vsa`.

---

### 🥞 2. Standalone Symbolic Stack Engine (`SymbolicStackEngine`)
Implemented a fine-grained, byte-level shadow stack simulator modeling x86-64 hardware physics and Little-Endian memory layout:

* **`strilight/engine/stack_engine.py` [NEW]**:
  * **`StackByteCell` Architecture**: Models individual byte cells with per-byte provenance metadata (`byte_ast`, `origin_instr`, `timestamp` tick, and `is_tainted` flag).
  * **Surgical Partial Overwrite & Byte-Level Stitching**:
    * Slices multi-byte values into Little-Endian bytes.
    * Reconstructs overlapping multi-byte words on-demand using `z3.Concat` (e.g. partial writes like `0xDE42DAEF`) without memory fragmentation or interval splitting.
  * **Hardware Stack Primitives**:
    * `push(val, size_bytes, origin_instr, timestamp)`: Adjusts RSP and writes cells.
    * `pop(size_bytes, origin_instr, timestamp)`: Reads cells and restores RSP.
    * `write_slot(offset, val, size_bytes)` & `read_slot(offset, size_bytes)`: Frame-pointer relative access.
    * `write_val(addr, val, size_bytes)` & `read_val(addr, size_bytes)`: Base memory access with fallback to `memory_provider`.
    * `get_provenance(addr, size_bytes)`: Deep inspection of instruction origins and timestamps.
* **`strilight/tests/unit/test_stack_engine.py` [NEW]**:
  * Comprehensive test suite validating concrete/symbolic push/pop, Little-Endian ordering, partial overwrite byte stitching, frame slot addressing, and provenance introspection.

---

### ⚡ 3. General SMT Translator & Core Integrations (`Z3Translator`)
* **`strilight/engine/translator.py` [MODIFY]**:
  * **Stack Engine Integration**: Delegated all memory operations (`load_memory`, `store_memory`, `_handle_push`, `_handle_pop`) directly to `SymbolicStackEngine`.
  * **Dynamic Operand Resolution (`_resolve_val_to_ast`)**:
    * Supports AST resolution for memory operand dictionaries (`{'type': 'mem', 'base': 'rbp', 'disp': -8}`) from live SSA state, preventing spurious zero fallbacks.
  * **Inter-Loop Scope Transition Protocol**:
    * Executes non-loop prologue instructions (`direct_records` such as `mov [rbp - 0xc], 0`) to initialize inner loop state.
    * Filters out self-accumulating induction steps (e.g. `add [rbp - 8], 1`) during prologue execution to prevent double-counting against closed-form loop formulas.
  * **Diagnostic UNSAT Tracking**: Labeled all assertions and invariants to produce detailed UNSAT core diagnostic explanations via `explain_unsat()`.
* **`strilight/engine/abstract_state.py` [MODIFY]**:
  * Added Bézout GCD modulo congruence non-alias checking (`is_disjoint_modulo`) and Must-Alias fast-paths in `read_memory`.
* **`strilight/engine/core.py` [MODIFY]**:
  * Dynamic memory provider binding: passes `self.se.mem_read` directly to `Tracker`.
* **`strilight/engine/instruction.py` [MODIFY]**:
  * Added `jump_taken` attribute directly into `Instruction.__init__`.
* **`strilight/engine/tracker.py` [MODIFY]**:
  * Added `memory_provider` parameter to `Tracker`, propagated into `LoopEvaluator` during backward and forward slicing phases.
* **`strilight/engine/x86_defs.py` [MODIFY]**:
  * Added `JCC_RELATIONAL_OPS` mapping conditional jump mnemonics (`je`, `jne`, `jg`, `jle`, `ja`, `jbe`, etc.) to relational operators (`eq`, `ne`, `gt`, `le`, etc.).
* **`strilight/__init__.py` [MODIFY]**:
  * Exported `SymbolicStackEngine` and `StackByteCell` in the public API and `__all__`.

---

### 🎯 4. Real-World CrackMe Benchmark Suite (`strilight/tests/benchmarks/`)
Integrated 7 real-world C-compiled x86-64 CrackMe challenges with automated ground truth verification:

* **`strilight/tests/benchmarks/CrackMeFile/` [NEW]**:
  * `crackme_boss.exe` / `.c`: Nested loops with 64,355 iterations and complex periodic stack accumulator (solved in $<0.2\text{s}$ with key `1729` and verified native `ACCESS GRANTED [PASS]`).
  * `crackme_subregs.exe` / `.c`: Subregister partial writes (AL/AH/EAX/RAX) and 32-bit zero-extension semantics (solved in $O(1)$ with key `1337`).
  * `crackme_license.exe` / `.c`: Stack variable license checking with non-trivial SMT bounds (solved in $O(1)$ with key `1337`).
  * `crackme_strided_circular.exe` / `.c`: Circular bitwise rotations, arithmetic shifts, and strided scaling (solved in $O(1)$ with key `1337`).
  * `crackme_telescoping.exe` / `.c`: Cascading telescoping recurrences (solved in $O(1)$ with key `1337`).
  * `crackme_nested_loops.exe` / `.c` & `crackme_pointers.exe` / `.c` **[WIP / Expected Failures]**: Complex multi-nested loop induction and indirect pointer arithmetic targets added as active benchmarks; their dedicated symbolic handlers are currently under active development.
* **`strilight/tests/benchmarks/test_library_full.py` [MODIFY]**:
  * End-to-end benchmark runner validating recovered keys via native OS execution.
  * Fixed relative `speakeasy` path resolution (3 levels up) to ensure 100% reproducible execution on clean git clones.
* **`strilight/tests/benchmarks/test_engine_full.py` [MODIFY]**:
  * Updated benchmark harness and verification routines.

---

### 🧪 5. Comprehensive Unit Test Suite
* **155 Passing Unit Tests in $<2\text{s}$ (100% Pass Rate)**:
  * **`test_stack_engine.py` [NEW]**: Shadow stack byte operations, Little-Endian packing, and provenance tracking.
  * **`test_compound_ast.py` [NEW]**: Hybrid affine and geometric algebraic compositions.
  * **`test_geometric_shift.py` [NEW]**: Exponential scale transformations and bit shifts.
  * **`test_strided_circular_scale.py` [NEW]**: Circular modular arithmetic.
  * **`test_symbolic_vsa.py` [NEW]**: Symbolic induction variable extraction.
  * **`test_telescoping_cascade.py` [NEW]**: Cascading multi-step recurrence invariants.

---

### 📚 6. Examples & Distribution
* **`examples/05_strided_circular_grand_challenge.py` [NEW]**:
  * End-to-end example demonstrating the solution of complex circular arithmetic loops in $O(1)$ time.
* **`examples/README.md` [MODIFY]**:
  * Documented the Grand Challenge example script and usage instructions.
* **`dist/strilight-0.1.0-py3-none-any.whl`**:
  * Verified isolated binary wheel packaging and clean execution directly from `site-packages`.
