import pytest
import logging
from strilight.frontend.source_lifter import SourceLifter, accelerate_c_source
import strilight as sl


def test_c_pragma_scalar_loop():
    """Verify #pragma strilight accelerate lifts a linear scalar loop into O(1)."""
    c_code = """
void update_score(int N) {
    int total = 0;
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        total += 5;
    }
    printf("%d\\n", total);
}
"""
    accelerated = accelerate_c_source(c_code)
    assert "#pragma strilight accelerate" not in accelerated
    assert "total += (5LL * N);" in accelerated
    assert "printf(" in accelerated


def test_c_pragma_coupled_matrix_loop():
    """Verify #pragma strilight accelerate lifts coupled variables into matrix exponentiation."""
    c_code = """
void simulate(int N) {
    uint32_t a = 1, b = 2;
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        next_a = 3*a + 7*b;
        next_b = -a + 4*b;
        a = next_a;
        b = next_b;
    }
}
"""
    accelerated = accelerate_c_source(c_code)
    assert "#pragma strilight accelerate" not in accelerated
    assert "Binary Matrix Exponentiation Engine" in accelerated or "sl_base" in accelerated


def test_c_pragma_array_constant_zero():
    """Verify #pragma strilight accelerate detects arr[i] = 0 and emits hardware memset."""
    c_code = """
void clear_buffer(int *arr, int N) {
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        arr[i] = 0;
    }
}
"""
    accelerated = accelerate_c_source(c_code)
    assert "#pragma strilight accelerate" not in accelerated
    assert "memset(arr, 0, (N) * sizeof(arr[0]));" in accelerated


def test_c_pragma_array_affine_progression():
    """Verify #pragma strilight accelerate detects arr[i] = 10 + i * 3."""
    c_code = """
void fill_affine(int *arr, int N) {
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        arr[i] = 10 + i * 3;
    }
}
"""
    accelerated = accelerate_c_source(c_code)
    assert "#pragma strilight accelerate" not in accelerated
    assert "arr[_i] = 10 + _i * 3;" in accelerated


def test_c_pragma_array_accumulate():
    """Verify #pragma strilight accelerate detects arr[i] += 7."""
    c_code = """
void add_delta(int *arr, int N) {
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        arr[i] += 7;
    }
}
"""
    accelerated = accelerate_c_source(c_code)
    assert "#pragma strilight accelerate" not in accelerated
    assert "arr[_i] += 7;" in accelerated


def test_c_pragma_graceful_fallback_on_unstructured_index(caplog):
    """Verify non-linear index arr[i * i] triggers graceful fallback with comment."""
    c_code = """
void complex_write(int *arr, int N) {
    #pragma strilight accelerate
    for (int i = 0; i < N; i++) {
        arr[i * i] = 99;
    }
}
"""
    with caplog.at_level(logging.WARNING):
        accelerated = accelerate_c_source(c_code)

    assert "Graceful fallback: non-linear loop preserved" in accelerated
    assert "arr[i * i] = 99;" in accelerated
    assert any("Unstructured or non-sequential" in rec.message for rec in caplog.records)


def test_top_level_import_export():
    """Verify accelerate_c_source is exported directly from strilight top-level."""
    assert callable(sl.accelerate_c_source)
    assert sl.accelerate_c_source is accelerate_c_source
