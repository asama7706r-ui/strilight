import pytest
import logging
from strilight.frontend.source_lifter import accelerate, SourceLifter


@accelerate
def fill_constant(arr, N):
    for i in range(N):
        arr[i] = 42


@accelerate
def fill_affine(arr, N):
    for i in range(N):
        arr[i] = i * 3 + 10


@accelerate
def add_to_elements(arr, N):
    for i in range(N):
        arr[i] += 7


def test_in_place_constant_array_mutation():
    """Verify in-place constant mutation arr[:N] = 42 preserves object identity."""
    data = [0] * 10
    original_id = id(data)

    fill_constant(data, 5)

    assert id(data) == original_id, "Array object identity MUST NOT change!"
    assert data[:5] == [42, 42, 42, 42, 42]
    assert data[5:] == [0, 0, 0, 0, 0]


def test_in_place_affine_array_mutation():
    """Verify in-place affine progression arr[:N] = i * 3 + 10 preserves object identity."""
    data = [0] * 8
    original_id = id(data)

    fill_affine(data, 6)

    assert id(data) == original_id, "Array object identity MUST NOT change!"
    assert data[:6] == [10, 13, 16, 19, 22, 25]
    assert data[6:] == [0, 0]


def test_in_place_accumulate_array_mutation():
    """Verify in-place accumulation arr[i] += 7 preserves object identity."""
    data = [1, 2, 3, 4, 5, 6]
    original_id = id(data)

    add_to_elements(data, 4)

    assert id(data) == original_id, "Array object identity MUST NOT change!"
    assert data == [8, 9, 10, 11, 5, 6]


def test_chained_loops_shared_array_junction():
    """Verify that Loop 1 mutating an array in-place is correctly observed by Loop 2."""
    @accelerate
    def pipeline(arr, N):
        # Loop 1: In-place array mutation
        for i in range(N):
            arr[i] = i * 5 + 2

    data = [0] * 10
    orig_id = id(data)
    pipeline(data, 8)

    assert id(data) == orig_id
    assert data[:8] == [2, 7, 12, 17, 22, 27, 32, 37]

    # Downstream consumer verifies updated elements
    total = sum(data[:8])
    assert total == 2 + 7 + 12 + 17 + 22 + 27 + 32 + 37


def test_graceful_fallback_on_unstructured_array_write(caplog):
    """Verify non-linear indexing arr[i * i] triggers graceful fallback with warning."""
    @accelerate
    def write_squared_index(arr, N):
        for i in range(N):
            arr[i * i] = 99

    data = [0] * 20
    with caplog.at_level(logging.WARNING):
        write_squared_index(data, 3)

    # Must log warning and still execute correctly via original fallback
    assert any("Unstructured or non-sequential" in rec.message for rec in caplog.records)
    assert data[0] == 99
    assert data[1] == 99
    assert data[4] == 99
    assert data[2] == 0


def test_graceful_fallback_on_complex_value(caplog):
    """Verify non-linear value formula arr[i] = i * i triggers graceful fallback with warning."""
    @accelerate
    def write_squared_value(arr, N):
        for i in range(N):
            arr[i] = i * i

    data = [0] * 5
    with caplog.at_level(logging.WARNING):
        write_squared_value(data, 4)

    assert any("Complex non-linear" in rec.message for rec in caplog.records)
    assert data[:4] == [0, 1, 4, 9]


def test_accelerate_attaches_mathematical_contract():
    """Verify @accelerate attaches _loop_summary and _invariant_contract for reflection."""
    @accelerate
    def sample_loop(arr, N):
        for i in range(N):
            arr[i] = 99

    assert hasattr(sample_loop, "_loop_summary"), "Function must carry its _loop_summary metadata!"
    assert hasattr(sample_loop, "_invariant_contract"), "Function must carry its _invariant_contract!"

    summary = sample_loop._loop_summary
    assert "arr" in summary.array_mutations
    assert summary.array_mutations["arr"].kind == "constant"
    assert summary.array_mutations["arr"].constant_val == 99

    contract = sample_loop._invariant_contract
    assert contract is not None
    contract_dict = contract.to_dict()
    assert "iron_constraint_rule" in contract_dict
