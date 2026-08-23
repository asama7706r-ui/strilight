import sys
import os
import z3
import pytest
import subprocess

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)

from strilight.engine.core import AnalyzerCore
from strilight.engine.hooks import setup_hooks
from strilight.engine.tracker import Descendant
from strilight.engine.translator import Z3Translator

TEST_CASES = [
    {
        "name": "crackme_boss",
        "exe": "crackme_boss.exe",
        "start_input": "1789",
        "target_cmp_pattern": "0xde42daef",
        "goal_value": 0xDE42DAEF,
        "key_bounds": (1000, 2000),
        "expected_key": 1729,
        "compress": True,
    },
    {
        "name": "crackme_subregs",
        "exe": "crackme_subregs.exe",
        "start_input": "1337",
        "target_cmp_pattern": "0xaa7a3a63",
        "goal_value": 0xAA7A3A63,
        "key_bounds": (1000, 9999),
        "expected_key": 1337,
    },
    {
        "name": "crackme_nested_loops",
        "exe": "crackme_nested_loops.exe",
        "start_input": "1337",
        "target_cmp_pattern": "0x2642564",
        "goal_value": 0x2642564,
        "key_bounds": (1000, 9999),
        "expected_key": 1337,
    },
    {
        "name": "crackme_pointers",
        "exe": "crackme_pointers.exe",
        "start_input": "1337",
        "target_cmp_pattern": "0x7f2a",
        "goal_value": 0x7F2A,
        "key_bounds": (1000, 9999),
        "expected_key": 1337,
    },
    {
        "name": "crackme_license",
        "exe": "crackme_license.exe",
        "start_input": "1337",
        "target_cmp_pattern": "-0xda942e",
        "goal_value": -14324782,
        "key_bounds": (1000, 9999),
        "expected_key": 1337,
    },
    {
        "name": "crackme_strided_circular",
        "exe": "crackme_strided_circular.exe",
        "start_input": "1337",
        "target_cmp_pattern": "0x55bbf9aa",
        "goal_value": 0x55BBF9AA,
        "key_bounds": (1000, 9999),
        "expected_key": 1337,
    }
]

@pytest.mark.skip(reason="End-to-end integration test suite. Run directly with python test_engine_full.py")
@pytest.mark.parametrize("test_case", TEST_CASES)
def test_crackme_solvers(test_case):
    res = run_crackme_case(test_case)
    assert res["sat"], f"Z3 failed to solve {test_case['name']}"
    assert res["native_pass"], f"Native binary rejected key {res['key']} for {test_case['name']}"

def run_crackme_case(test_case):
    target_exe = test_case["exe"]
    crackme_dir = os.path.join(app_dir, "strilight", "tests", "CrackMeFile")
    target_path = os.path.join(crackme_dir, target_exe)
    
    result = {
        "name": test_case["name"],
        "exe": target_exe,
        "slice_len": 0,
        "sat": False,
        "key": None,
        "native_pass": False,
        "native_output": ""
    }
    
    print(f"\n[*] Initializing AnalyzerCore with Speakeasy backend for {target_exe}...")
    core = AnalyzerCore(target_path=[str(target_path), str(test_case["start_input"])])
    
    print("[*] Setting up hooks...")
    setup_hooks(core)
    
    print("[*] Starting emulation...")
    core.start()
    
    print(f"[*] Emulation completed. Total ticks traced: {core.tick_counter}")
    
    # Check if cmp is in the trace history
    target_tick = -1
    for record in reversed(core.tracker.trace_history):
        if record.mnemonic == "cmp":
            op_str_lower = record.op_str.lower()
            if test_case["target_cmp_pattern"].lower() in op_str_lower:
                target_tick = record.tick
                break
                
    assert target_tick != -1, f"[-] Target not found for {target_exe}!"

    # Compress loops if requested by test case
    if test_case.get("compress", False):
        print("\n[*] Compressing trace history...")
        core.tracker.compress_trace()

    print(f"[SUCCESS] Target CMP instruction found at Tick {target_tick}!")
    
    target_record = core.tracker.get_trace_at_tick(target_tick)
    if target_record and target_record.operands:
        op0 = target_record.operands[0]
        if op0.get('type') == 'reg':
            desc = Descendant(target=op0['value'], at_tick=target_tick, is_memory=False)
        elif op0.get('type') == 'mem' and target_record.mem_read:
            desc = Descendant(target=target_record.mem_read[0], at_tick=target_tick, is_memory=True)
        else:
            desc = Descendant(target="eax", at_tick=target_tick)
    else:
        desc = Descendant(target="eax", at_tick=target_tick)

    slice_records = core.tracker.build_backward_slice(desc)
    result["slice_len"] = len(slice_records)
    
    print("\n[+] ===========================================")
    print(f"[+] Final Slice Extracted ({len(slice_records)} instructions)")
    
    chronological_slice = list(reversed(slice_records))
    
    translator = Z3Translator(memory_provider=core.se.mem_read)
    
    print("[+] Concretizing initial zero time moments (_t0)...")
    for reg, val in core.initial_regs.items():
        val_ast = z3.BitVecVal(val, 64)
        translator.reg_state[reg] = val_ast
        translator.solver.add(z3.BitVec(f"{reg}_t0", 64) == val)
        
    key_var = z3.BitVec("key_input", 32)
    translator.target_vars.add(key_var)
    translator.add_tracked_constraint(key_var >= test_case["key_bounds"][0], "Key Lower Bound")
    translator.add_tracked_constraint(key_var < test_case["key_bounds"][1], "Key Upper Bound")
    
    # 1. Look for explicit input boundary tagged by STOP_FUNCTIONS / hooks.py
    input_boundary_tick = None
    for r in core.tracker.trace_history:
        if getattr(r, 'is_input_boundary', False):
            input_boundary_tick = r.tick
            print(f"[+] Found Input Boundary API ({getattr(r, 'api_name', 'unknown')}) at Tick {r.tick}")
            break

    # 2. Find the verification function prologue immediately following the input boundary
    check_key_start_tick = None
    if input_boundary_tick is not None:
        for r in chronological_slice:
            if hasattr(r, 'tick') and r.tick > input_boundary_tick:
                if hasattr(r, 'mnemonic') and r.mnemonic == 'push' and 'rbp' in r.op_str:
                    check_key_start_tick = r.tick
                    break

    # 3. Fallback to first push rbp after CRT startup (> tick 700)
    if check_key_start_tick is None:
        for r in chronological_slice:
            if hasattr(r, 'tick') and r.tick > 700:
                if hasattr(r, 'mnemonic') and r.mnemonic == 'push' and 'rbp' in r.op_str:
                    check_key_start_tick = r.tick
                    break

    for record in chronological_slice:
        if record.tick == target_tick:
            record.requested_flags = ["flag_zf", "flag_cf", "flag_sf", "flag_of"]
        
        if hasattr(record, 'mnemonic') and record.mnemonic.startswith('j') and record.mnemonic != 'jmp':
            if record.tick < check_key_start_tick:
                record.jump_taken = None 

        if record.tick == target_tick + 1:
            if record.jump_taken is not None:
                record.jump_taken = not record.jump_taken
                print(f"[!] Flipped target jump at Tick {record.tick} to force winning path!")
                
        if hasattr(record, 'mnemonic'):
            translator.parse_instruction(record)
        else:
            translator.translate_loop_summary(record, max_iterations=getattr(record, 'iterations', 1000))
        
        if record.tick == check_key_start_tick:
            translator.reg_state["ecx"] = key_var
            translator.reg_state["rcx"] = z3.ZeroExt(32, key_var)
            print(f"[+] Injected symbolic key into ecx/rcx at Tick {record.tick} (check_key prologue)")
    
    tgt = test_case["goal_value"]
    if target_record and target_record.operands:
        op0 = target_record.operands[0]
        final_val, bit_size = translator._read_operand(op0)
        if final_val is not None:
            tgt_ast = z3.BitVecVal(tgt, bit_size)
            print(f"[+] Adding Goal Constraint: {op0} == {hex(tgt) if tgt >= 0 else tgt}")
            translator.add_tracked_constraint(final_val == tgt_ast, f"Goal Target: {tgt}")

    print("\n[*] Z3 Solving...")
    res = translator.solver.check()
    if res == z3.sat:
        result["sat"] = True
        model = translator.solver.model()
        for d in model.decls():
            if d.name() == "key_input":
                recovered_key = model[d].as_long()
                result["key"] = recovered_key
                print(f"[SUCCESS] Discovered key_input = {recovered_key}")
                break
                
        # Native Ground-Truth Validation
        if result["key"] is not None:
            try:
                proc = subprocess.run([target_path, str(result["key"])], capture_output=True, text=True, timeout=5)
                output = proc.stdout.strip()
                result["native_output"] = output
                if "ACCESS GRANTED" in output:
                    result["native_pass"] = True
                    print(f"[GROUND TRUTH] Native binary returned: '{output}' -> [VERIFIED]")
                else:
                    print(f"[GROUND TRUTH] Native binary returned: '{output}' -> [FAILED]")
            except Exception as e:
                result["native_output"] = str(e)
                print(f"[-] Native execution error: {e}")
    else:
        print("[-] Z3 returned UNSAT!")

    return result

def print_summary_table(results):
    print("\n" + "=" * 92)
    print("                     [CRACKME SUITE BENCHMARK & VERIFICATION RESULTS]")
    print("=" * 92)
    print(f"{'#':<3} | {'Target Name':<22} | {'Slice':<7} | {'Z3 Status':<10} | {'Discovered Key':<15} | {'Native Test':<13} | {'Result':<8}")
    print("-" * 92)
    
    all_passed = True
    for idx, r in enumerate(results, 1):
        z3_status = "SAT" if r["sat"] else "UNSAT"
        key_str = str(r["key"]) if r["key"] is not None else "N/A"
        native_str = "GRANTED" if r["native_pass"] else ("DENIED" if r["key"] is not None else "N/A")
        overall_pass = r["sat"] and r["native_pass"]
        if not overall_pass:
            all_passed = False
        res_tag = "[PASS]" if overall_pass else "[FAIL]"
        
        print(f"{idx:<3} | {r['name']:<22} | {r['slice_len']:<7} | {z3_status:<10} | {key_str:<15} | {native_str:<13} | {res_tag:<8}")
        
    print("=" * 92)
    if all_passed:
        print("[+] ALL CRACKME TEST CASES FULLY SOLVED AND VERIFIED AGAINST NATIVE BINARIES!")
    else:
        print("[-] SOME TEST CASES FAILED VERIFICATION. CHECK DETAILS ABOVE.")
    print("=" * 92 + "\n")

if __name__ == '__main__':
    results = []
    for idx, tc in enumerate(TEST_CASES, 1):
        print(f"\n{'=' * 60}")
        print(f"[{idx}/{len(TEST_CASES)}] Processing CrackMe: {tc['name']} ({tc['exe']})")
        print(f"{'=' * 60}")
        res = run_crackme_case(tc)
        results.append(res)
        
    print_summary_table(results)
