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