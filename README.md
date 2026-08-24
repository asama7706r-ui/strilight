# 🌟 Strilight

<p align="center">
  <strong>High-Performance $O(1)$ SMT Loop Lifting & Strided Interval Domain for x86_64 Binary Analysis</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-Alpha%20%2F%20Research%20Prototype-yellow.svg" alt="Status">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/unit%20tests-147%20passed%20%7C%20100%25-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/lifting-Zero--Unroll%20O(1)-orange.svg" alt="Lifting Mode">
  <img src="https://img.shields.io/badge/disassembler-Capstone%20Native-purple.svg" alt="Capstone">
  <img src="https://img.shields.io/badge/architecture-x86__64-red.svg" alt="Arch">
</p>

> [!WARNING]
> **Project Status (Alpha / Research Prototype):**
> Strilight is currently in its early **Alpha phase**. It is a focused research implementation providing strong empirical proof of concept and mathematical foundations for eliminating the classical **Loop & Path Explosion Problem** via $O(1)$ SMT closed-form lifting. We actively welcome feedback, test cases, and community contributions!

---

## 📖 1. Overview & The Core Problem

Traditional Symbolic Execution and Dynamic Binary Instrumentation (DBI) engines (such as *angr*, *Triton*, or *KLEE*) suffer from the notorious **Path & Loop Explosion Problem**. When encountering a loop executing $N = 100,000$ iterations, classical engines unroll the loop iteration-by-iteration, generating hundreds of thousands of SSA variables and causing SMT solvers to hang or exhaust memory.

**Strilight** solves this fundamentally by treating loops as **closed-form algebraic recurrences** within the **Strided Interval Domain**:

$$\vec{\mathbf{R}}(N) = \vec{\mathbf{R}}_0 + \vec{\boldsymbol{\Delta}} \cdot N$$

Instead of simulating $N$ iterations, **Strilight** compresses repetitive execution traces into hierarchical `LoopBlock` structures, evaluates their abstract affine & polycyclic steps, and lifts the entire loop directly into an **$O(1)$ Closed-Form SMT Equation**.

---

## ⚡ 2. Key Architectural Innovations

1. **Zero-Unroll Trace Compression:** Identifies back-edges and compresses millions of linear instruction traces into compact hierarchical `LoopBlock` graphs in $<1\text{ ms}$.
2. **Strided Interval Domain & Dual-Mask VSA:** Tracks register and memory transformations using strides and modular congruences:
   $$s[l, u] = \{ x \mid l \le x \le u \land (x - l) \equiv 0 \pmod s \}$$
3. **Polycyclic & Periodic Pattern Extraction:** Detects complex cyclic memory and sub-register transformations ($P > 1$).
4. **The Iron Invariant Contract:** Formulates the exact first-exit boundary condition to prevent SMT solvers from "teleporting" through loop termination bounds:
   $$\text{ExitCondition}(\text{State}(N)) \land \forall k < N, \neg \text{ExitCondition}(\text{State}(k))$$
5. **Decoupled Modular Architecture:** Native Capstone disassembly with pluggable custom tracer bridges.

---

## 🚀 3. Modular Distribution Profiles

**Strilight** is packaged as independent modular profiles so you only carry the components your pipeline needs:

```bash
# Profile 1: Core Engine (Pure Compressor + Embedded Def-Use Slicer + Capstone)
pip install strilight

# Profile 2: Symbolic Engine (Core Compressor + Z3 O(1) SMT Lifter)
pip install strilight[solver]

# Profile 3: Dynamic Slicing Suite (Core Compressor + Full PathTree Backward/Forward Tracker)
pip install strilight[tracker]

# Profile 4: Complete Bundle (All Engines + Full Tracker + Z3 Solver)
pip install strilight[all]
```

---

## 🧪 4. Test Suite Taxonomy & Verification

The test suite validates every module with 100% test pass rate across the decoupled layers:

### Tier 1: Core Compressor & Abstract Interpretation Tests (Requires `strilight`)
*Zero heavy solver dependencies. Runs in $<1\text{ second}$ on any platform:*

| Test File | Description | Components Tested |
| :--- | :--- | :--- |
| [`test_facade.py`](file:///d:/work_app/MyApp/strilight/tests/test_facade.py) | High-level developer API (`sl.analyze`, `sl.disassemble`, `sl.compress`, `sl.evaluate`) | `strilight` Facade |
| [`test_capstone_decoupling.py`](file:///d:/work_app/MyApp/strilight/tests/test_capstone_decoupling.py) | Raw machine code bytes disassembly & custom tracer bridge registration | `Instruction`, `TrackerBridge` |
| [`test_invariant_contract.py`](file:///d:/work_app/MyApp/strilight/tests/test_invariant_contract.py) | Mathematical invariant contracts & $N-1$ Iron Constraint boundary descriptors | `LoopInvariantContract` |
| [`test_interval.py`](file:///d:/work_app/MyApp/strilight/tests/test_interval.py) | Core interval bounding, interval arithmetic, and operations | `Interval` |
| [`test_disjoint_set.py`](file:///d:/work_app/MyApp/strilight/tests/test_disjoint_set.py) | Disjoint memory sets, non-contiguous range arithmetic, and unions | `DisjointIntervalSet` |
| [`test_strided_interval_notion.py`](file:///d:/work_app/MyApp/strilight/tests/test_strided_interval_notion.py) | Strided Interval domain, GCD congruence bridge, and sub-register bitmasks | `StridedInterval` |
| [`test_circular_theorems.py`](file:///d:/work_app/MyApp/strilight/tests/test_circular_theorems.py) | Circular modular arithmetic wrap-around theorems ($x \pmod{2^w}$) | `StridedInterval` Math |
| [`test_loop_compressor.py`](file:///d:/work_app/MyApp/strilight/tests/test_loop_compressor.py) | Trace folding and loop back-edge detection into `LoopBlock` trees | `TraceCompressor` |
| [`test_nested_loops.py`](file:///d:/work_app/MyApp/strilight/tests/test_nested_loops.py) | Multi-level nested loop compression ($O(N \cdot M)$ hierarchical folding) | `TraceCompressor` Trees |
| [`test_vsa_evaluator.py`](file:///d:/work_app/MyApp/strilight/tests/test_vsa_evaluator.py) | Value-Set Analysis simulation passes and affine delta extraction | `LoopEvaluator` |
| [`test_polycyclic.py`](file:///d:/work_app/MyApp/strilight/tests/test_polycyclic.py) | Polycyclic periodic patterns in memory & registers ($P > 1$) | `LoopEvaluator` |

---

### Tier 2: Dynamic Slicing & Dependency Tracker Tests (Requires `strilight[tracker]`)
*Validates full dynamic data-flow and control-dependency tracking:*

| Test File | Description | Components Tested |
| :--- | :--- | :--- |
| [`test_tracker.py`](file:///d:/work_app/MyApp/strilight/tests/test_tracker.py) | Backward/forward instruction slicing, register/memory def-use chains | `Tracker`, `BackwardTracker` |
| [`test_lazy_tracker.py`](file:///d:/work_app/MyApp/strilight/tests/test_lazy_tracker.py) | Lazy evaluation and irrelevant loop block skipping | `Tracker` Optimization |
| [`test_loop_taint.py`](file:///d:/work_app/MyApp/strilight/tests/test_loop_taint.py) | Loop taint propagation and loop-exit control dependency tracking | `Tracker` Taint |
| [`test_path_tree.py`](file:///d:/work_app/MyApp/strilight/tests/test_path_tree.py) | Branch decision caching and dead-end path elimination | `PathTree` |
| [`test_stop_dict.py`](file:///d:/work_app/MyApp/strilight/tests/test_stop_dict.py) | API taint boundary definitions | `stop_dict` |
| [`test_hooks.py`](file:///d:/work_app/MyApp/strilight/tests/test_hooks.py) | Instruction and memory access interception callbacks | `hooks` |

---

### Tier 3: Symbolic SMT Lifter & Solver Tests (Requires `strilight[solver]`)
*Validates BitVector equation generation, shadow substitutions, and Z3 constraint solving:*

| Test File | Description | Components Tested |
| :--- | :--- | :--- |
| [`test_translator.py`](file:///d:/work_app/MyApp/strilight/tests/test_translator.py) | Full x86-64 instruction translation to Z3 BitVectors (arithmetic, flags, jumps, memory) | `Z3Translator` |
| [`test_translator_edge_cases.py`](file:///d:/work_app/MyApp/strilight/tests/test_translator_edge_cases.py) | Deep AST exhaustion, memory aliasing chains, and boundary constraints | `Z3Translator` Edge Cases |
| [`test_deep_doubts.py`](file:///d:/work_app/MyApp/strilight/tests/test_deep_doubts.py) | Signed wrap-around, degree-3 cubic Newton induction, and Bezout congruences | Mathematical Proofs |

---

## 💡 5. Quickstart: 3 Ways to Use Strilight

### Option A: One-Line Loop Analysis (`sl.analyze`)
Analyze any raw x86-64 machine code loop and extract its closed-form transformation in a single line:

```python
import strilight as sl

# Loop bytecode: add eax, 8; sub ebx, 3; inc ecx; cmp ecx, 100000; jl 0x1000
loop_bytes = bytes.fromhex("83c008 83eb03 ffc1 81f9a0860100 7ced")

# ONE-LINE ANALYSIS:
summary = sl.analyze(loop_bytes, iterations=100000)

print(summary.deltas)
# Output: {'eax': 8, 'ebx': -3, 'ecx': 1}

# View the mathematical invariant contract:
print(summary.invariant_contract.to_dict())
```

---

### Option B: Disassemble, Compress & Evaluate Step-by-Step

```python
import strilight as sl

# 1. Disassemble machine code bytes
instructions = sl.disassemble(loop_bytes, base_address=0x1000)

# 2. Package into a symbolic loop block
block = sl.LoopBlock(body=instructions, iterations=100000)

# 3. Extract closed-form mathematical steps (Deltas & Exit Predicates)
summary = sl.evaluate(block)
print(f"Exit Condition: {summary.exit_condition}")
```

---

### Option C: Instant $O(1)$ SMT Solving with Z3

Solve for the number of iterations ($N$) or the input key required to satisfy a goal condition in $<100\text{ ms}$:

```python
import strilight as sl
import z3

# Disassemble and evaluate
summary = sl.analyze(loop_bytes, iterations=100000)

# Initialize Z3 translator
translator = sl.Z3Translator()
translator.solver.add(translator.get_register('eax') == 0)
translator.solver.add(translator.get_register('ebx') == 500000)
translator.solver.add(translator.get_register('ecx') == 0)

# Lift loop summary in O(1) into Z3
translator.translate_loop_summary(summary, max_iterations=100000)

# Goal: When does EAX reach 800,000?
translator.solver.add(translator.get_register('eax') == 800000)

# Solve in milliseconds!
if translator.solver.check() == z3.sat:
    model = translator.solver.model()
    solved_N = model.eval(summary.loop_counter_var).as_long()
    print(f"[+] Solved N = {solved_N:,} iterations in O(1) time!")
```

---

## 📊 6. Real-World Binary Benchmark Results

Tested against complex 64-bit Windows executables (`CrackMe Suite`) containing nested loops, sub-register slicing, and obfuscated stride patterns:

| # | Target Binary | Slice Size | Z3 Status | Discovered Key | Native Execution | Time | Result |
|---|---------------|------------|-----------|----------------|------------------|------|--------|
| 1 | `crackme_boss.exe` | 662 | **SAT** | `1729` | `ACCESS GRANTED` | **~60 ms** | **[PASS]** |
| 2 | `crackme_subregs.exe` | 671 | **SAT** | `1337` | `ACCESS GRANTED` | **~75 ms** | **[PASS]** |
| 3 | `crackme_nested_loops.exe` | 1369 | **SAT** | `1337` | `ACCESS GRANTED` | **~110 ms** | **[PASS]** |
| 4 | `crackme_pointers.exe` | 859 | **SAT** | `1337` | `ACCESS GRANTED` | **~85 ms** | **[PASS]** |
| 5 | `crackme_license.exe` | 657 | **SAT** | `1337` | `ACCESS GRANTED` | **~65 ms** | **[PASS]** |
| 6 | `crackme_strided_circular.exe` | 829 | **SAT** | `1337` | `ACCESS GRANTED` | **~95 ms** | **[PASS]** |

> **Ground-Truth Verification:** All recovered keys are verified by executing the native compiled binary (`.exe`) via subprocess and asserting the `ACCESS GRANTED` response.

---

## 📚 7. API Reference

### High-Level Facade Functions:
* `sl.analyze(code_bytes, iterations=1000, ...)`: One-liner disassembly + evaluation.
* `sl.disassemble(code_bytes, base_address=0x1000, bit_mode=64)`: Raw byte disassembler via Capstone.
* `sl.compress(trace, min_iterations=3)`: Hierarchical trace compressor.
* `sl.evaluate(block_or_trace, k_passes=100)`: Abstract state & invariant evaluator.

### Core Classes:
* `sl.Instruction`: Unified assembly instruction representation.
* `sl.LoopBlock`: Hierarchical loop node with iteration bounds.
* `sl.LoopSummary`: Closed-form transformation summary containing deltas, cyclic patterns, and constant sets.
* `sl.LoopInvariantContract`: Formal structural exit invariant descriptor and SMT boundary rule generator.
* `sl.StridedInterval`: Mathematical interval representation with stride alignment and modular congruence.
* `sl.Z3Translator`: Symbolic SMT lifter converting loop summaries to Z3 BitVector constraints.

---

## 📄 License
Dual License: MIT / Proprietary.
Developed with ❤️ for high-performance reverse engineering and binary analysis.
