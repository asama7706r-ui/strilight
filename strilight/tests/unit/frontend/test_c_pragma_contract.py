"""
Strilight C Pragma Contract & Cross-File Header Resolution Tests
================================================================
Validates OpenMP-style Developer Contracts for C loops:
- #pragma strilight accelerate target(...) include(...) model(...)
- Static resolution of #define and const symbols from C headers
- Closed-form synthesis driven by explicit developer contracts
"""

import os
import tempfile
import pytest

from strilight.frontend.c.contract import parse_c_pragma_contract, CPragmaContract
from strilight.frontend.resolver import CrossFileResolver
from strilight.frontend.c.lifter import CLoopLifter
from strilight.frontend.source_lifter import SourceLifter


def test_parse_c_pragma_contract():
    # 1. Full contract
    clause = 'target(bodies) include("solar.h") model(cascade)'
    contract = parse_c_pragma_contract(clause)
    assert contract.target == "bodies"
    assert contract.include_file == "solar.h"
    assert contract.model == "cascade"
    assert not contract.is_empty()

    # 2. Partial contract
    clause2 = 'target(arr)'
    contract2 = parse_c_pragma_contract(clause2)
    assert contract2.target == "arr"
    assert contract2.include_file is None
    assert contract2.model is None
    assert not contract2.is_empty()

    # 3. Empty clause
    contract3 = parse_c_pragma_contract("")
    assert contract3.target is None
    assert contract3.include_file is None
    assert contract3.is_empty()


def test_resolve_constants_from_c_content():
    c_header = """
    // Configuration Header
    #define STEPS 1000
    #define MULT 2
    #define TOTAL_STEPS (STEPS * MULT)
    #define DELTA 5LL
    
    static const int THREADS = 8;
    const double EPSILON = 1e-5;
    """
    constants = CrossFileResolver.resolve_constants_from_c_content(c_header)
    assert constants["STEPS"] == 1000
    assert constants["MULT"] == 2
    assert constants["TOTAL_STEPS"] == 2000
    assert constants["DELTA"] == 5
    assert constants["THREADS"] == 8
    assert constants["EPSILON"] == 1e-5


def test_c_loop_lifter_with_scope_env():
    c_loop = """
    for (int i = 0; i < N_STEPS; i++) {
        total += STEP_INC;
    }
    """
    contract = CPragmaContract(target="total", model="linear")
    scope_env = {"N_STEPS": 500, "STEP_INC": 10}

    lifter = CLoopLifter()
    summary = lifter.lift(c_loop, contract=contract, scope_env=scope_env)

    assert summary.iterations == 500
    assert summary.contract is not None
    assert summary.contract.target == "total"
    assert summary.target_collection == "total"
    assert "total" in summary.var_exprs
    # total should have incremented by 10 each step
    term = summary.var_exprs["total"].terms[0]
    assert term.stride == 10


def test_accelerate_c_source_with_contract_and_header():
    with tempfile.TemporaryDirectory() as tmpdir:
        header_path = os.path.join(tmpdir, "config.h")
        with open(header_path, "w", encoding="utf-8") as f:
            f.write("""
            #define N_ITERS 1000
            #define STEP 3
            """)

        header_path_esc = header_path.replace("\\", "/")

        c_source = f"""
        #include <stdio.h>
        
        int main() {{
            int acc = 0;
            #pragma strilight accelerate target(acc) include("{header_path_esc}")
            for (int i = 0; i < N_ITERS; i++) {{
                acc += STEP;
            }}
            printf("%d\\n", acc);
            return 0;
        }}
        """

        accelerated = SourceLifter.accelerate_c_source(c_source)

        assert "/* [strilight] Contract Accelerated O(1)/O(log N) kernel */" in accelerated
        assert "for (int i = 0; i < N_ITERS; i++)" not in accelerated
        # Verify closed form statement is present: acc += (3LL * 1000);
        assert "acc +=" in accelerated
        assert "3LL * 1000" in accelerated or "3000" in accelerated or "1000" in accelerated


def test_accelerate_c_source_array_contract():
    with tempfile.TemporaryDirectory() as tmpdir:
        header_path = os.path.join(tmpdir, "params.h")
        with open(header_path, "w", encoding="utf-8") as f:
            f.write("""
            #define SIZE 256
            #define VAL 42
            """)

        header_path_esc = header_path.replace("\\", "/")

        c_source = f"""
        void update(int *arr) {{
            #pragma strilight accelerate target(arr) include("{header_path_esc}")
            for (int i = 0; i < SIZE; i++) {{
                arr[i] += VAL;
            }}
        }}
        """

        accelerated = SourceLifter.accelerate_c_source(c_source)
        assert "/* [strilight] Contract Accelerated O(1)/O(log N) kernel */" in accelerated
        assert "arr[_i] += 42" in accelerated
