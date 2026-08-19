import pytest
from asm_analyzer.pruning.interval import Interval

def test_interval_intersect_normal():
    # Test intersection of two overlapping intervals
    i1 = Interval(10, 20)
    i2 = Interval(15, 25)
    i3 = i1.intersect(i2)
    
    assert i3.min_val == 15
    assert i3.max_val == 20
    assert i3.bit_width == 64

def test_interval_intersect_subset():
    # Test when one interval is a subset of another
    i1 = Interval(10, 30)
    i2 = Interval(15, 20)
    i3 = i1.intersect(i2)
    
    assert i3.min_val == 15
    assert i3.max_val == 20

def test_interval_intersect_no_overlap():
    # Test when intervals do not overlap (conflict / dead path)
    i1 = Interval(10, 20)
    i2 = Interval(30, 40)
    i3 = i1.intersect(i2)
    
    assert i3.min_val == 0
    assert i3.max_val == 0

def test_interval_intersect_different_bit_widths():
    # Test that assertion error is raised for different bit widths
    i1 = Interval(10, 20, bit_width=32)
    i2 = Interval(10, 20, bit_width=64)
    
    with pytest.raises(AssertionError, match="Cannot intersect intervals of different bit widths"):
        i1.intersect(i2)

