# 💡 Strilight Examples & Quickstart Scripts

This directory contains standalone, practical examples showcasing the core features and APIs of **Strilight**.

---

## 📜 Example Catalog

| Script | Description | Focus API / Component |
| :--- | :--- | :--- |
| [`01_quickstart_analyze.py`](./01_quickstart_analyze.py) | One-line analysis of x86_64 loop bytecode. | `sl.analyze`, `LoopSummary` |
| [`02_step_by_step_evaluation.py`](./02_step_by_step_evaluation.py) | Disassembly, packaging into `LoopBlock`, and VSA evaluation. | `sl.disassemble`, `sl.LoopBlock`, `sl.evaluate` |
| [`03_z3_symbolic_solving.py`](./03_z3_symbolic_solving.py) | Lifting loop transformations to Z3 and solving in $O(1)$ without unrolling. | `sl.Z3Translator`, `sl.translate_loop_summary` |
| [`04_strided_interval_pruning.py`](./04_strided_interval_pruning.py) | Strided intervals, Bézout GCD arithmetic, and modulo congruence pruning. | `StridedInterval`, `DisjointIntervalSet` |
| [`05_strided_circular_grand_challenge.py`](./05_strided_circular_grand_challenge.py) | 1,000,000-Iteration Strided Circular array and geometric shift benchmark. | `StridedInterval`, `LoopSummary`, `Z3Translator` |

---

## 🚀 How to Run

Make sure you have `strilight` installed (with optional dependencies for solver scripts):

```bash
# Run Example 01 (Quickstart Analysis):
python examples/01_quickstart_analyze.py

# Run Example 02 (Step-by-step Evaluation):
python examples/02_step_by_step_evaluation.py

# Run Example 03 (Z3 SMT Solving):
python examples/03_z3_symbolic_solving.py

# Run Example 04 (Strided Interval Pruning):
python examples/04_strided_interval_pruning.py

# Run Example 05 (1 Million-Iteration Strided Circular Challenge):
python examples/05_strided_circular_grand_challenge.py
```
