import pytest
import logging
from strilight.engine.domains import StridedInterval
from strilight.engine.vsa import ArrayDescriptor, LoopSummary


def test_array_descriptor_creation():
    """Verify ArrayDescriptor initialization, bounds, and cycle_sum computation."""
    table = [10, 25, 40, 15]
    desc = ArrayDescriptor("lookup_table", length=len(table), elements=table)

    assert desc.name == "lookup_table"
    assert desc.length == 4
    assert desc.bounds_interval.min_val == 0
    assert desc.bounds_interval.max_val == 3
    assert desc.bounds_interval.stride == 1
    assert desc.cycle_sum == 90  # 10 + 25 + 40 + 15
    assert desc.elements == [10, 25, 40, 15]


def test_array_descriptor_in_bounds_intersection():
    """Verify in-bounds indices pass through untouched."""
    desc = ArrayDescriptor("handlers", length=16)

    # Index stride 2: 0, 2, 4, 6, 8, 10
    idx = StridedInterval(0, 10, bit_width=64, stride=2)
    assert desc.is_in_bounds(idx) is True

    res = desc.intersect_index(idx)
    assert res.min_val == 0
    assert res.max_val == 10
    assert res.stride == 2


def test_array_descriptor_partial_intersection():
    """Verify partial overlap narrows bounds to array limits."""
    desc = ArrayDescriptor("buffer", length=10)  # Bounds: [0, 9]

    # Index range: [5, 15]
    idx = StridedInterval(5, 15, bit_width=64, stride=1)
    assert desc.is_in_bounds(idx) is False

    res = desc.intersect_index(idx)
    assert res.min_val == 5
    assert res.max_val == 9
    assert res.stride == 1


def test_array_descriptor_out_of_bounds_warning(caplog):
    """Verify complete out-of-bounds access logs a warning and marks dead path."""
    desc = ArrayDescriptor("sbox", length=8)  # Bounds: [0, 7]

    # Index range completely outside: [20, 30]
    idx = StridedInterval(20, 30, bit_width=64, stride=1)
    assert desc.is_in_bounds(idx) is False

    with caplog.at_level(logging.WARNING):
        res = desc.intersect_index(idx)

    assert any("OUT OF BOUNDS" in rec.message for rec in caplog.records)


def test_array_descriptor_zero_length_warning(caplog):
    """Verify zero-length arrays handle indexing gracefully with warning."""
    desc = ArrayDescriptor("empty_arr", length=0)
    assert desc.length == 0

    idx = StridedInterval(0, 5, bit_width=64, stride=1)
    with caplog.at_level(logging.WARNING):
        desc.intersect_index(idx)

    assert any("zero-length" in rec.message for rec in caplog.records)


def test_array_descriptor_loop_summary_integration():
    """Verify LoopSummary manages ArrayDescriptor instances."""
    summary = LoopSummary()
    desc = ArrayDescriptor("global_table", length=32, elements=[i * 2 for i in range(32)])

    summary.array_descriptors["global_table"] = desc
    assert "global_table" in summary.array_descriptors
    assert summary.array_descriptors["global_table"].length == 32
    assert summary.array_descriptors["global_table"].cycle_sum == sum(i * 2 for i in range(32))

    data_dict = desc.to_dict()
    assert data_dict["name"] == "global_table"
    assert data_dict["length"] == 32
    assert data_dict["bounds"] == [0, 31]
    assert data_dict["stride"] == 1
