# Project full name: Optimized Unrolling & Symbolic Analysis Memory Architecture

# 📝 Project Report: Optimizing Symbolic Execution for Complex Programs

## 1. Introduction

This project implements a symbolic execution engine, focusing on translating x86-64 assembly instructions into Z3 constraints to perform program analysis and solve constraints. It relies on the `z3-solver` for constraint satisfaction, and uses `speakeasy` for emulation and dynamic binary instrumentation. 

## 2. Architecture Overview
The engine's architecture is primarily organized within the `asm_analyzer/engine/` module:

*   **`AnalyzerCore` (`core.py`)**: The main controller. It wraps the `speakeasy` emulator, loads the binary or shellcode, initializes memory footprint hashing, and starts the emulation process. It also manages the execution tick counter and coordinates the tracking.
*   **`Hooks` (`hooks.py`)**: Registers callbacks with `speakeasy` to intercept execution at the instruction level (`hook_code`) and memory access level (`hook_mem_read`, `hook_mem_write`). It utilizes `capstone` to disassemble instructions, track register reads/writes, and populate the trace history.
*   **`Tracker` (`tracker.py`)**: The central nervous system for execution history. It records every instruction executed as a `TraceRecord`. It supports Backward Slicing to trace data dependencies from a specific target register/memory address back to its origins.
*   **`Translator` (`translator.py`)**: The symbolic execution core. The `Z3Translator` maps x86-64 instructions to Z3 BitVector and Boolean equations. It models physical registers, maps mathematical operations (`add`, `sub`, `xor`, `mul`), flag updates (ZF, CF, SF, OF), shift operations, and control-flow jumps to SMT constraints.
*   **`PathTree` (`path_tree.py`)**: Manages path caching and dead-end tracking to optimize branch exploration and avoid state explosion or redundant constraint generation.
*   **`Stop Dictionary` (`stop_dict.py`)**: Defines API boundaries (like `scanf`, `printf`) where the engine should break taint, pause, or handle interactive I/O during emulation.

## 3. Key Concepts

### 3.1 Trace Recording and Hooking
Execution is tracked by injecting hooks via `speakeasy`. For every instruction, Capstone extracts the operands and read/write dependencies. This information is saved in the `Tracker`.

### 3.2 Backward Slicing
To avoid modeling the entire execution path, the engine implements Backward Slicing. When a target condition is hit (e.g., a specific `cmp` instruction), the tracker walks backward through the trace history, finding only the instructions that directly or indirectly influence the target register, significantly reducing the size of the constraint formula.

### 3.3 Symbolic Translation
The `Z3Translator` takes the sliced instructions and maps them chronologically to Z3. It handles Static Single Assignment (SSA) internally by creating new Z3 variables for every register modification, ensuring mathematical accuracy without overwriting past states. 

### 3.4 Smart Concretization
During symbolic translation, memory reads might encounter symbolic addresses. The engine attempts "Smart Concretization" by evaluating the address in the current Z3 model and falling back to querying the emulator's memory space if the address resolves to a concrete, static pointer.

## 4. Running Tests
The project uses `pytest` for unit testing to ensure the correctness of the engine components.

Execute the unit tests using the following command from the repository root:
```bash
PYTHONPATH=. python3 -m pytest asm_analyzer/tests/
```
