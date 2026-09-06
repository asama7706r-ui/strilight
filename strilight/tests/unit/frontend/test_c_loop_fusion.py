import pytest
import subprocess
import shutil
import strilight as sl
from strilight.frontend import CLoopLifter


def test_c_struct_member_lifting():
    lifter = CLoopLifter()
    code = """
    void f(int N) {
        for (int i = 0; i < N; i++) {
            body->p += 10;
        }
    }
    """
    summary = lifter.lift(code)
    assert "body->p" in summary.var_exprs
    assert summary.var_exprs["body->p"].terms[0].stride == 10


def test_c_struct_member_coupled():
    lifter = CLoopLifter()
    code = """
    void f(int N) {
        for (int i = 0; i < N; i++) {
            body->p += body->v;
            body->v += -2;
        }
    }
    """
    summary = lifter.lift(code)
    assert summary.coupling_matrix is not None
    assert "body->p" in summary.coupling_matrix.vars
    assert "body->v" in summary.coupling_matrix.vars


def test_c_loop_fusion_directive():
    c_source = """
    void simulate(int N) {
        #pragma strilight fuse
        for (int i = 0; i < N; i++) {
            pos_x += vel_x;
        }
        for (int i = 0; i < N; i++) {
            vel_x += -10;
        }
    }
    """
    accelerated = sl.accelerate_c_source(c_source)
    assert "/* [strilight] Fused Accelerated O(1)/O(log N) kernel */" in accelerated
    # Verify both loops were replaced
    assert accelerated.count("for (int i = 0; i < N; i++)") == 0
    assert "pos_x" in accelerated
    assert "vel_x" in accelerated


def test_c_loop_fusion_with_struct_fields():
    c_source = """
    void update(int N) {
        #pragma strilight fuse(target: body)
        for (int i = 0; i < N; i++) {
            body->pos += body->vel;
        }
        for (int i = 0; i < N; i++) {
            body->vel += -5;
        }
    }
    """
    accelerated = sl.accelerate_c_source(c_source)
    assert "/* [strilight] Fused Accelerated O(1)/O(log N) kernel */" in accelerated
    assert "body->pos" in accelerated
    assert "body->vel" in accelerated


@pytest.mark.skipif(shutil.which("gcc") is None, reason="GCC not installed")
def test_c_loop_fusion_gcc_parity(tmp_path):
    c_code = """
    #include <stdio.h>
    #include <stdint.h>

    int main() {
        uint32_t p = 100, v = 50;
        int N = 1000;
        #pragma strilight fuse
        for (int i = 0; i < N; i++) {
            p += v;
        }
        for (int i = 0; i < N; i++) {
            v += 2;
        }
        printf("%u %u\\n", p, v);
        return 0;
    }
    """
    accelerated = sl.accelerate_c_source(c_code)
    src_file = tmp_path / "fused_test.c"
    exe_file = tmp_path / "fused_test.exe"
    src_file.write_text(accelerated, encoding="utf-8")

    compile_res = subprocess.run(["gcc", "-O3", str(src_file), "-o", str(exe_file)], capture_output=True, text=True)
    assert compile_res.returncode == 0, f"Compilation failed: {compile_res.stderr}"

    run_res = subprocess.run([str(exe_file)], capture_output=True, text=True)
    assert run_res.returncode == 0

    # Calculate expected mathematical baseline
    exp_p = 100
    exp_v = 50
    for _ in range(1000):
        exp_p = (exp_p + exp_v) & 0xFFFFFFFF
        exp_v = (exp_v + 2) & 0xFFFFFFFF

    out_p, out_v = map(int, run_res.stdout.strip().split())
    assert (out_p, out_v) == (exp_p, exp_v)
