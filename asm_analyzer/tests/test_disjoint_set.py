import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from asm_analyzer.pruning.interval import Interval, DisjointIntervalSet

def test_disjoint_set_k_limit():
    dset = DisjointIntervalSet(k_limit=3)
    
    # Add 3 distinct intervals
    dset.add(Interval(10, 20))
    dset.add(Interval(30, 40))
    dset.add(Interval(50, 60))
    
    # Should still be disjoint (3 distinct intervals)
    assert len(dset.intervals) == 3
    
    # Add a 4th interval. This exceeds k_limit=3, should trigger convex_hull
    dset.add(Interval(70, 80))
    
    assert len(dset.intervals) == 1
    merged = dset.intervals[0]
    
    # The merged interval should bound all 4 intervals
    assert merged.min_val == 10
    assert merged.max_val == 80

def test_disjoint_set_stride_preservation():
    dset = DisjointIntervalSet(k_limit=2)
    
    # Both have stride=4, offset=2
    dset.add(Interval(10, 14, stride=4, stride_offset=2))
    dset.add(Interval(22, 26, stride=4, stride_offset=2))
    
    # Still disjoint
    assert len(dset.intervals) == 2
    
    # Add a 3rd with same stride
    dset.add(Interval(34, 38, stride=4, stride_offset=2))
    
    # Triggers convex hull
    assert len(dset.intervals) == 1
    merged = dset.intervals[0]
    
    # Should preserve the stride!
    assert merged.min_val == 10
    assert merged.max_val == 38
    assert merged.stride == 4
    assert merged.stride_offset == 2

def test_disjoint_set_stride_destruction():
    dset = DisjointIntervalSet(k_limit=2)
    
    dset.add(Interval(10, 14, stride=4, stride_offset=2))
    dset.add(Interval(22, 26, stride=4, stride_offset=2))
    # Different stride
    dset.add(Interval(35, 39, stride=1, stride_offset=0))
    
    merged = dset.intervals[0]
    # Stride should be destroyed/reverted to 1
    assert merged.stride == 1
    assert merged.stride_offset == 0

def test_interval_intersect_stride():
    i1 = Interval(10, 50, stride=4, stride_offset=2) # 10, 14, 18, 22
    i2 = Interval(10, 50, stride=4, stride_offset=0) # 12, 16, 20, 24
    
    res = i1.intersect(i2)
    # Different offsets for same stride means no intersection! Dead path.
    assert res.min_val == 0
    assert res.max_val == 0

if __name__ == "__main__":
    pytest.main(["-v", __file__])
