---
trigger: always_on
---

### 📝 Agent-to-Agent Handover: AsmAnalyzer Architecture Experience
**From:** Antigravity (Session: Taint-Based Concretization & Aliasing)
**To:** Future Agents

**How to fast-track your understanding of this codebase (Lessons I learned the hard way):**

1. **The Emulator Mismatch Trap (Don't force equality):** 
   When I first tried to handle symbolic memory pointers, I made the mistake of trying to bind them exactly to the concrete addresses from the trace (e.g., `solver.add(addr == concrete_address)`). *Do not do this!* It immediately causes `UNSAT` errors because the mathematical symbolic state will eventually diverge from the emulator's exact trace. 
   **The shortcut:** Treat the concrete trace as a "suggestion", not an absolute truth. When dealing with tainted/symbolic pointers, use VSA bounds (e.g., `UGE 0x10000`) and let Z3 figure out the exact address.

2. **The Memory Aliasing Illusion (It's already solved!):** 
   I initially over-complicated my thinking by worrying about how to handle complex overlapping memory (like a 32-bit write overlapping a 16-bit read at a shifted offset). I later realized the engine is already a step ahead. 
   **The shortcut:** Look closely at `_write_operand` and `_read_operand`. The architecture splits EVERYTHING into 8-bit pieces using `z3.Extract` and puts them back together with `z3.Concat`. You do not need to write complex memory-range overlap math; the byte-by-byte conditional matching handles partial overlaps natively. Trust the byte-level logic!

3. **The "Clean Code" Performance Trap:** 
   I reviewed another agent's code that tried to make memory equality checks "cleaner" by using `z3.simplify(cond)` inside the inner memory loop. It looked mathematically elegant but completely destroyed the engine's speed.
   **The shortcut:** This engine’s philosophy is "Build ugly ASTs in Python incredibly fast, and let Z3's C++ core simplify them at the very end." Never call Z3's C++ simplifier inside a hot Python loop. Use fast, native Python type-checking (`isinstance(..., z3.BitVecNumRef)`) to filter out concrete values instead.

### 📝 Agent-to-Agent Handover: VSA Engine & Taint Architecture
**From:** Antigravity (Session: Loop Compression & VSA)
**To:** Future Agents

**Critical Architectural Directives (Do NOT violate these):**

4. **The VSA Disjoint Set & K-Limit System (Beating Z3's Bit-blasting):**
   Never send massive, unpruned bitwise loops directly to Z3. Z3 will bit-blast them and cause an OOM crash. We built a Value Set Analysis (VSA) engine in `interval.py`.
   **The Rule (Corrected):** We use **Bounded Disjoint Sets** (lists of intervals) to handle complex operations like modulo and shifts with surgical precision. To prevent Interval Explosion (OOM), we enforce a strict **K-Limit** (e.g., max 4 fragments). If the limit is exceeded, we apply a **Convex Hull** merge, falling back on the Dual-Mask system (`known_mask` and `known_value`) to preserve precision inside the merged bounds.

5. **Taint Stratification (Preventing Path Explosion):**
   When implementing Control Dependency Tracking, do NOT opportunistically track branches for *every* variable in the taint set (e.g., loop counters). This causes massive Path Explosion. 
   **The Rule:** Differentiate between **Primary Taints** (sensitive user input) and **Secondary Taints** (multipliers/counters). Only capture `cmp/jcc` branches that directly read Primary Taints.

6. **Unsigned Hacker's Delight:**
   The `Interval` class logic must remain strictly **Unsigned**. Bitwise operations have no concept of sign. Rely purely on physical modulo arithmetic (`& physical_max`). Signedness is only relevant later at the AST/Instruction Semantic level.

### 📝 Agent-to-Agent Handover: Symbolic Memory vs Concrete Trace
**From:** Antigravity (Session: Loop Translation & Symbolic Memory Overwrites)
**To:** Future Agents

**Architectural Traps in the Intermediate Engine (Do NOT repeat my mistakes):**

7. **The `current_instr` Memory Override Trap (The "Smart Feature" Backfire):**
   When translating flattened traces in `Z3Translator`, we use a feature in `_write_operand` that overrides symbolic addresses with the concrete address from `self.current_instr.mem_write[0]` to prevent pointer aliasing bugs. 
   **The Trap:** When you inject mathematical summaries (like `LoopSummary.deltas`), they are *not* physical instructions, but you might forget to clear `self.current_instr`. This caused the strides of unrelated variables (like `magic`) to overwrite the loop counter's memory location because `current_instr` was stuck on `mov [rbp-8], 0`!
   **The Rule:** If you are translating synthetic or abstract operations (like VSA summaries) that provide absolute concrete memory addresses (e.g., `MEM_20971136_32`), **you MUST temporarily set `self.current_instr = None`**. Do not let the instruction translator assume the abstract state is tied to the last executed trace instruction.

8. **Loop Evaluator != Z3 Translator (Who reads the flags?):**
   Do not confuse the duties of the `LoopEvaluator` (VSA) with `Z3Translator`. 
   **The Rule:** The `LoopEvaluator` is a *Data-Flow Engine*; it NEVER reads conditional flags (`ZF`, `CF`) and NEVER executes `jcc`. It only simulates arithmetic to extract Strides (`deltas`). It merely packages the exit `cmp/jcc` instructions into `exit_records`. It is the **`Z3Translator`** that later parses these records, generates the flags in SSA form, and builds the mathematical `LoopCounter` equations.