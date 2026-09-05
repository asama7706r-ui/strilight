"""
High-Level Benchmark: Multi-Variable Coupled Matrix Recurrence Speedup
======================================================================
Measures execution time and speedup across 3 tiers for a 4-variable coupled system
over N = 1,000,000 iterations:

  * Tier 1: Original O(N) iterative loop.
  * Tier 2: Dynamic O(log N) Binary Matrix Exponentiation (Symbolic runtime N).
  * Tier 3: Precomputed O(1) Closed-Form Statement Synthesis (Static N).

Compares Python execution against Native C (compiled via GCC -O2) and verifies
100% bit-exact correctness across all 3 tiers.
"""

import time
import subprocess
import os
import tempfile
from strilight.frontend import SourceLifter, CodeGenerator


def benchmark_python(N: int = 1_000_000):
    print("=========================================================================")
    print(f"   [TIER 1 -> TIER 2 -> TIER 3 BENCHMARK: PYTHON (N = {N:,})]   ")
    print("=========================================================================")

    # 1. Tier 1: Original O(N) Loop
    def run_tier1_python(iterations, a, b, c, d):
        for _ in range(iterations):
            next_a = (3*a + 7*b - 2*c + 5*d + 11) & 0xFFFFFFFF
            next_b = (-2*a + 5*b + 8*c - d + 17) & 0xFFFFFFFF
            next_c = (4*a - b + 6*c + 3*d + 23) & 0xFFFFFFFF
            next_d = (a + 9*b - 4*c + 2*d + 31) & 0xFFFFFFFF
            a, b, c, d = next_a, next_b, next_c, next_d
        return a, b, c, d

    t0 = time.perf_counter()
    r1 = run_tier1_python(N, 1, 2, 3, 4)
    t1_time = (time.perf_counter() - t0) * 1000

    # 2. Tier 2: Dynamic O(log N) Binary Exponentiation
    py_code_symbolic = """
for _ in range(N):
    next_a = 3*a + 7*b - 2*c + 5*d + 11
    next_b = -2*a + 5*b + 8*c - d + 17
    next_c = 4*a - b + 6*c + 3*d + 23
    next_d = a + 9*b - 4*c + 2*d + 31
    a, b, c, d = next_a, next_b, next_c, next_d
"""
    summary_sym = SourceLifter.lift_python_loop(py_code_symbolic)
    sym_stmts = CodeGenerator.to_python_statements(summary_sym, N_var="N", in_place=True)

    tier2_func_code = f"""
def run_tier2_python(N, a, b, c, d):
{chr(10).join('    ' + line for line in sym_stmts.splitlines())}
    return a, b, c, d
"""
    local_env2 = {}
    exec(tier2_func_code, {}, local_env2)
    run_tier2_python = local_env2["run_tier2_python"]

    # Warmup
    run_tier2_python(N, 1, 2, 3, 4)
    t0 = time.perf_counter()
    r2 = run_tier2_python(N, 1, 2, 3, 4)
    t2_time = (time.perf_counter() - t0) * 1000

    # 3. Tier 3: Static O(1) Precomputed Closed Form
    summary_static = SourceLifter.lift_python_loop(py_code_symbolic)
    static_stmts = CodeGenerator.to_python_statements(summary_static, N_var=str(N), in_place=True)
    tier3_func_code = f"""
def run_tier3_python(a, b, c, d):
{chr(10).join('    ' + line for line in static_stmts.splitlines())}
    return a & 0xFFFFFFFF, b & 0xFFFFFFFF, c & 0xFFFFFFFF, d & 0xFFFFFFFF
"""
    local_env3 = {}
    exec(tier3_func_code, {}, local_env3)
    run_tier3_python = local_env3["run_tier3_python"]

    # Warmup
    run_tier3_python(1, 2, 3, 4)
    t0 = time.perf_counter()
    r3 = run_tier3_python(1, 2, 3, 4)
    t3_time = (time.perf_counter() - t0) * 1000

    print(f"[*] Tier 1: Original O(N) Execution Time:         {t1_time:.4f} ms")
    print(f"[*] Tier 2: Dynamic O(log N) Binary Exp Time:      {t2_time:.4f} ms  ({t1_time/max(t2_time, 1e-6):,.0f}x faster)")
    print(f"[*] Tier 3: Precomputed O(1) Closed Form Time:     {t3_time:.6f} ms  ({t1_time/max(t3_time, 1e-6):,.0f}x faster)")
    print(f"[+] Exactness: Tier 1 == Tier 2 == Tier 3? -> {r1 == r2 == r3} (a=0x{r1[0]:08X}, b=0x{r1[1]:08X}, c=0x{r1[2]:08X}, d=0x{r1[3]:08X})\n")


def benchmark_native_c(N: int = 1_000_000):
    print("=========================================================================")
    print(f"   [TIER 1 -> TIER 2 -> TIER 3 BENCHMARK: NATIVE C (GCC -O2, N = {N:,})]   ")
    print("=========================================================================")

    py_code = """
for _ in range(N):
    next_a = 3*a + 7*b - 2*c + 5*d + 11
    next_b = -2*a + 5*b + 8*c - d + 17
    next_c = 4*a - b + 6*c + 3*d + 23
    next_d = a + 9*b - 4*c + 2*d + 31
    a, b, c, d = next_a, next_b, next_c, next_d
"""
    summary = SourceLifter.lift_python_loop(py_code)
    tier2_c_body = CodeGenerator.to_c_statements(summary, N_var="N", in_place=True)
    tier3_c_body = CodeGenerator.to_c_statements(summary, N_var=str(N), in_place=True)

    c_source = f"""
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

static double get_time_ms(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER freq) {{
    return ((double)(end.QuadPart - start.QuadPart) * 1000.0) / (double)freq.QuadPart;
}}

int main() {{
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    uint32_t a1 = 1, b1 = 2, c1 = 3, d1 = 4;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < {N}; i++) {{
        uint32_t na = 3*a1 + 7*b1 - 2*c1 + 5*d1 + 11;
        uint32_t nb = -2*a1 + 5*b1 + 8*c1 - d1 + 17;
        uint32_t nc = 4*a1 - b1 + 6*c1 + 3*d1 + 23;
        uint32_t nd = a1 + 9*b1 - 4*c1 + 2*d1 + 31;
        a1 = na; b1 = nb; c1 = nc; d1 = nd;
    }}
    QueryPerformanceCounter(&t1);
    double tier1_time = get_time_ms(t0, t1, freq);

    uint32_t a2, b2, c2, d2;
    {{
        uint32_t a = 1, b = 2, c = 3, d = 4;
        uint64_t N = {N};
        QueryPerformanceCounter(&t0);
{chr(10).join('        ' + line for line in tier2_c_body.splitlines())}
        a2 = a; b2 = b; c2 = c; d2 = d;
        QueryPerformanceCounter(&t1);
    }}
    double tier2_time = get_time_ms(t0, t1, freq);

    uint32_t a3, b3, c3, d3;
    {{
        uint32_t a = 1, b = 2, c = 3, d = 4;
        QueryPerformanceCounter(&t0);
{chr(10).join('        ' + line for line in tier3_c_body.splitlines())}
        a3 = a; b3 = b; c3 = c; d3 = d;
        QueryPerformanceCounter(&t1);
    }}
    double tier3_time = get_time_ms(t0, t1, freq);

    printf("[*] Tier 1: Original O(N) Execution Time:         %.4f ms\\n", tier1_time);
    printf("[*] Tier 2: Dynamic O(log N) Binary Exp Time:      %.4f ms  (%.0fx faster)\\n", tier2_time, tier1_time / (tier2_time > 1e-6 ? tier2_time : 1e-6));
    printf("[*] Tier 3: Precomputed O(1) Closed Form Time:     %.6f ms  (%.0fx faster)\\n", tier3_time, tier1_time / (tier3_time > 1e-6 ? tier3_time : 1e-6));
    printf("[+] Bit-Exact Match: %s (a=0x%08X, b=0x%08X, c=0x%08X, d=0x%08X)\\n\\n",
           (a1 == a2 && a2 == a3 && b1 == b2 && b2 == b3 && c1 == c2 && c2 == c3 && d1 == d2 && d2 == d3) ? "TRUE" : "FALSE",
           a1, b1, c1, d1);
    return 0;
}}
"""
    tmp_c = os.path.join(tempfile.gettempdir(), "benchmark_coupled_c.c")
    tmp_exe = os.path.join(tempfile.gettempdir(), "benchmark_coupled_c.exe")
    with open(tmp_c, "w") as f:
        f.write(c_source)

    try:
        subprocess.check_call(["gcc", "-O2", tmp_c, "-o", tmp_exe])
        res = subprocess.check_output([tmp_exe]).decode()
        print(res)
    finally:
        for f in (tmp_c, tmp_exe):
            if os.path.exists(f):
                os.remove(f)


if __name__ == "__main__":
    benchmark_python(1_000_000)
    benchmark_native_c(1_000_000)
