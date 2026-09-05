# Strilight C Developer Contracts & Pragma Acceleration Guide

This directory contains standalone, practical examples demonstrating **Developer Contracts** for C source code in Strilight (`#pragma strilight accelerate` and `#pragma strilight fuse`).

---

## 1. Architectural Motivation

In Python, loops operate in an interpreted, dynamic runtime environment where objects, variable scopes, and global constants can be inspected via reflection. 

In C, source code is statically compiled. Loop induction variables, array pointer boundaries, and loop limits frequently reside across separate header files (`#define`, `const`), or involve complex pointer mutations.

To achieve exact $O(1)$ and $O(\log N)$ closed-form acceleration on C loops without runtime overhead or unsafe execution, Strilight implements **Developer-Contract-Guided Lifting**:
1. The developer attaches an explicit pragma directive directly above the loop.
2. The contract specifies the reduction or mutation target, the associated header files, and the recurrence model.
3. Strilight statically parses the C Abstract Syntax Tree (AST) using `pycparser`, resolves header constants via `CrossFileResolver`, and synthesizes a closed-form replacement block in-place.

---

## 2. Pragma Grammar & Contract Syntaxes

Strilight parses developer contracts using two standardized syntaxes:

### Syntax A: OpenMP-Style Clauses
```c
#pragma strilight accelerate target(variable) include("header.h") model(linear)
for (int i = 0; i < N; i++) {
    variable += STEP;
}
```

### Syntax B: Explicit Contract Wrapper
```c
#pragma strilight accelerate contract(target=variable, include="header.h", model=linear)
for (int i = 0; i < N; i++) {
    variable += STEP;
}
```

### Syntax C: Loop Fusion Directive
```c
#pragma strilight fuse target(array_name)
for (int i = 0; i < N; i++) {
    array_name[i] += 10;
}
for (int i = 0; i < N; i++) {
    array_name[i] += 25;
}
```

---

## 3. Supported Clauses & Parameters

| Clause | Synonyms | Purpose & Semantics |
| :--- | :--- | :--- |
| `target(...)` | `entities(...)` | Designates the primary scalar variable, array, struct collection, or comma-separated list of entities modified inside the loop body. Examples: `target(total)`, `target(buffer)`, `target(bodies)`, or `target(x, y, z)`. |
| `include("path")` | `file("path")`, `header("path")` | Directs Strilight to statically parse `#define` macros and `const` declarations from the specified header file using `CrossFileResolver`. No runtime code is executed. |
| `model(name)` | `rule(name)` | Specifies the mathematical recurrence model to guide the synthesis: <br>• `linear`: Single-pass affine stride accumulation.<br>• `cascade`: Multi-variable telescoping polynomial recurrence.<br>• `coupled`: Multi-variable coupled linear system. |

### Multi-Target & Collective Entity Referencing
Strilight's developer contract supports referencing multiple objects/entities at two distinct structural levels:

1. **Collective Struct Containers (`target(name)` / `entities(name)`)**:
   When simulating physical or geometric systems represented as an array of structs (e.g., `bodies[i].x`, `bodies[i].vx`):
   ```c
   #pragma strilight accelerate target(bodies) include("solar.h") model(coupled)
   for (int i = 0; i < N_BODIES; i++) {
       bodies[i].x += bodies[i].vx * DT;
   }
   ```
   Strilight binds `bodies` as the target collection and extracts all internal mutated fields in parallel.

2. **Comma-Separated Multi-Entity Lists (`target(a, b, ...)` / `entities(...)`)**:
   When multiple coupled variables evolve together:
   ```c
   #pragma strilight accelerate target(pos, vel) model(coupled)
   for (int i = 0; i < N; i++) {
       pos += vel * DT;
       vel += ACC * DT;
   }
   ```
   The contract extracts `pos` and `vel`, sets up the multi-dimensional transition matrix $\mathbf{A} \in \mathbb{Q}^{2 \times 2}$, and computes their simultaneous state at iteration $N$ via matrix exponentiation $\mathbf{A}^N$ in $O(\log N)$.


---

## 4. Included Examples

### Example 1: Scalar Reduction with Cross-File Header Resolution
- **Directory**: `01_scalar_reduction/`
- **Files**:
  - `config.h`: Declares `#define N_STEPS 1000000000ULL` and `#define STEP_INC 7LL`.
  - `scalar_kernel.c`: Contains `#pragma strilight accelerate target(total) include("config.h") model(linear)`.
- **Transformation Result**:
  The iterative loop of 1,000,000,000 cycles is replaced by:
  ```c
  /* [strilight] Contract Accelerated O(1)/O(log N) kernel */
  {
      total += (7LL * N_STEPS);
  }
  ```

### Example 2: In-Place Array Mutation
- **Directory**: `02_array_mutation/`
- **Files**:
  - `matrix_params.h`: Declares `#define ARRAY_SIZE 1024` and `#define INITIAL_OFFSET 42`.
  - `array_kernel.c`: Contains `#pragma strilight accelerate target(buffer) include("matrix_params.h")`.
- **Transformation Result**:
  Strilight lifts the sequential loop into a vectorized in-place slice mutation:
  ```c
  /* [strilight] Contract Accelerated O(1)/O(log N) kernel */
  {
      for (int _i = 0; _i < (ARRAY_SIZE); _i++) { buffer[_i] += 42; }
  }
  ```

### Example 3: Loop Fusion
- **Directory**: `03_loop_fusion/`
- **Files**:
  - `fusion_kernel.c`: Contains two sequential loops with `#pragma strilight fuse target(stream)`.
- **Transformation Result**:
  Strilight fuses both passes into a single optimized pass:
  ```c
  /* [strilight] Contract Accelerated O(1)/O(log N) kernel */
  {
      for (int _i = 0; _i < (count); _i++) { stream[_i] += 25; }
  }
  ```

---

## 5. Running the Demonstration

To execute the automated demonstration runner across all C examples:

```bash
python examples/c/run_c_acceleration.py
```

To accelerate any C source code file programmatically in Python:

```python
import strilight as sl

with open("path/to/source.c", "r") as f:
    c_source = f.read()

# Synthesize closed-form C kernels in-place
accelerated_c = sl.accelerate_c_source(c_source)

with open("path/to/source_accelerated.c", "w") as f:
    f.write(accelerated_c)
```

---

## 6. Compiler Compatibility

Because `#pragma` directives that are unrecognized by standard compilers are ignored by default in C99/C11/C17 (`-Wno-unknown-pragmas`), source code containing `#pragma strilight` directives remains 100% compliant with standard C compilers (GCC, Clang, MSVC) prior to or after acceleration preprocessing.
