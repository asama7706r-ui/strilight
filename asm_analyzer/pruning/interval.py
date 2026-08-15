from typing import Optional, List

class Interval:
    """
    Physical Hardware-Encoded Interval with 3-Valued Logic (Bit-wise Abstract Domain).
    Represents the mathematical bounds of a variable/register alongside its physical constraints.
    """
    def __init__(self, min_val: int, max_val: int, bit_width: int = 64, known_mask: int = 0, known_value: int = 0, stride: int = 1, stride_offset: int = 0):
        self.bit_width = bit_width
        self.physical_max = (1 << bit_width) - 1
        
        # Modulo Arithmetic (Strides)
        self.stride = stride
        self.stride_offset = stride_offset & self.physical_max
        
        # Dual-Mask System for 3-Valued Logic
        self.known_mask = known_mask & self.physical_max
        self.known_value = known_value & self.known_mask
        
        self.min_val = min_val & self.physical_max
        self.max_val = max_val & self.physical_max
        
        # Normalize bounds safely
        if self.min_val > self.max_val:
            self.min_val, self.max_val = 0, self.physical_max
            
        # Bi-directional VSA Pruning
        self._interval_to_mask()
        self._mask_to_interval()

    def _mask_to_interval(self):
        """Prunes min_val and max_val using the 3-Valued Logic mask."""
        if self.known_mask == 0:
            return
            
        unknown_mask = (~self.known_mask) & self.physical_max
        
        # Force known bits into min and max
        self.min_val = (self.min_val & unknown_mask) | self.known_value
        self.max_val = (self.max_val & unknown_mask) | self.known_value
        
        if self.min_val > self.max_val:
            self.min_val, self.max_val = min(self.min_val, self.max_val), max(self.min_val, self.max_val)

    def _interval_to_mask(self):
        """Deduces common known bits from min_val and max_val."""
        diff = self.min_val ^ self.max_val
        
        # Find the highest differing bit to create a mask of all bits below it
        v = diff
        v |= v >> 1
        v |= v >> 2
        v |= v >> 4
        v |= v >> 8
        v |= v >> 16
        v |= v >> 32
        
        # Bits that are strictly identical for the entire interval
        inferred_mask = (~v) & self.physical_max
        
        self.known_mask |= inferred_mask
        self.known_value = (self.known_value & (~inferred_mask)) | (self.min_val & inferred_mask)
        self.known_value &= self.known_mask

    def __repr__(self):
        stride_str = f" Stride:{self.stride}(+{self.stride_offset})" if self.stride > 1 else ""
        return f"<Interval [{hex(self.min_val)}, {hex(self.max_val)}] Mask:{hex(self.known_mask)} Val:{hex(self.known_value)}{stride_str} ({self.bit_width}-bit)>"

    def intersect(self, other: 'Interval') -> 'Interval':
        """Intersects this interval with another to narrow down possibilities."""
        assert self.bit_width == other.bit_width, "Cannot intersect intervals of different bit widths."
        
        new_min = max(self.min_val, other.min_val)
        new_max = min(self.max_val, other.max_val)
        
        # Stride intersection logic
        new_stride = self.stride
        new_stride_offset = self.stride_offset
        if self.stride != other.stride or self.stride_offset != other.stride_offset:
            if self.stride == 1:
                new_stride = other.stride
                new_stride_offset = other.stride_offset
            elif other.stride == 1:
                pass
            else:
                # If they are exactly the same stride but different offset, they never intersect!
                if self.stride == other.stride and self.stride_offset != other.stride_offset:
                    return Interval(0, 0, self.bit_width) # Dead Path
                # For complex differing strides, fallback to stride=1 for safety
                new_stride = 1
                new_stride_offset = 0
        
        new_mask = self.known_mask | other.known_mask
        new_value = (self.known_value | other.known_value) & new_mask
        
        if new_min > new_max:
            return Interval(0, 0, self.bit_width) # Dead Path
            
        return Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride, stride_offset=new_stride_offset)

    # =========================================================================
    # Forward Operations (VSA Abstract Semantics)
    # =========================================================================

    def add(self, other: 'Interval') -> 'DisjointIntervalSet':
        assert self.bit_width == other.bit_width
        dset = DisjointIntervalSet(k_limit=8)
        
        # Dual-mask heuristic for addition (safest approximation)
        new_mask = 0
        new_value = 0
        if self.known_mask == self.physical_max and other.known_mask == other.physical_max:
            new_mask = self.physical_max
            new_value = (self.known_value + other.known_value) & self.physical_max

        new_min = self.min_val + other.min_val
        new_max = self.max_val + other.max_val
        
        # Handle wrap-around (Overflow splits interval)
        if new_max <= self.physical_max:
            dset.add(Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value))
        else:
            if new_min <= self.physical_max:
                dset.add(Interval(new_min, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value))
                dset.add(Interval(0, new_max & self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value))
            else:
                dset.add(Interval(new_min & self.physical_max, new_max & self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value))
        return dset

    def sub(self, other: 'Interval') -> 'DisjointIntervalSet':
        assert self.bit_width == other.bit_width
        dset = DisjointIntervalSet(k_limit=8)
        
        new_mask = 0
        new_value = 0
        if self.known_mask == self.physical_max and other.known_mask == other.physical_max:
            new_mask = self.physical_max
            new_value = (self.known_value - other.known_value) & self.physical_max
            
        new_min = self.min_val - other.max_val
        new_max = self.max_val - other.min_val
        
        # Handle underflow
        if new_min >= 0:
            dset.add(Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value))
        else:
            if new_max >= 0:
                dset.add(Interval(0, new_max, self.bit_width, known_mask=new_mask, known_value=new_value))
                dset.add(Interval((new_min + self.physical_max + 1) & self.physical_max, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value))
            else:
                dset.add(Interval((new_min + self.physical_max + 1) & self.physical_max, (new_max + self.physical_max + 1) & self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value))
        return dset

    def bitwise_and(self, other: 'Interval') -> 'Interval':
        assert self.bit_width == other.bit_width
        # Dual-Mask precision for AND
        known_zeros_self = self.known_mask & (~self.known_value)
        known_zeros_other = other.known_mask & (~other.known_value)
        known_ones_self = self.known_mask & self.known_value
        known_ones_other = other.known_mask & other.known_value
        
        new_known_zeros = (known_zeros_self | known_zeros_other) & self.physical_max
        new_known_ones = (known_ones_self & known_ones_other) & self.physical_max
        new_mask = new_known_zeros | new_known_ones
        new_value = new_known_ones
        
        # The result of unsigned AND is bounded by the smallest max value
        new_max = min(self.max_val, other.max_val)
        new_min = 0
        
        return Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def bitwise_or(self, other: 'Interval') -> 'Interval':
        assert self.bit_width == other.bit_width
        known_ones_self = self.known_mask & self.known_value
        known_ones_other = other.known_mask & other.known_value
        known_zeros_self = self.known_mask & (~self.known_value)
        known_zeros_other = other.known_mask & (~other.known_value)
        
        new_known_ones = (known_ones_self | known_ones_other) & self.physical_max
        new_known_zeros = (known_zeros_self & known_zeros_other) & self.physical_max
        new_mask = new_known_ones | new_known_zeros
        new_value = new_known_ones
        
        # The result of unsigned OR is at least the largest min value
        new_min = max(self.min_val, other.min_val)
        new_max = self.physical_max
        
        return Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def bitwise_xor(self, other: 'Interval') -> 'Interval':
        assert self.bit_width == other.bit_width
        # XOR is known only if both corresponding bits are strictly known
        new_mask = self.known_mask & other.known_mask
        new_value = (self.known_value ^ other.known_value) & new_mask
        
        new_min = 0
        new_max = self.physical_max
        
        return Interval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    # =========================================================================
    # Inverse Operations (Backward Slicing Algebra)
    # =========================================================================

    def add_inverse(self, constant: int) -> 'Interval':
        new_min = (self.min_val - constant) & self.physical_max
        new_max = (self.max_val - constant) & self.physical_max
        new_offset = (self.stride_offset - constant) % self.stride if self.stride > 1 else 0
        return Interval(new_min, new_max, self.bit_width, stride=self.stride, stride_offset=new_offset)

    def sub_inverse(self, constant: int) -> 'Interval':
        new_min = (self.min_val + constant) & self.physical_max
        new_max = (self.max_val + constant) & self.physical_max
        new_offset = (self.stride_offset + constant) % self.stride if self.stride > 1 else 0
        return Interval(new_min, new_max, self.bit_width, stride=self.stride, stride_offset=new_offset)

    def and_inverse(self, constant: int) -> 'Interval':
        """If self = X AND C, finding X from Y"""
        new_mask = constant & self.physical_max
        new_value = self.known_value & new_mask
        return Interval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def or_inverse(self, constant: int) -> 'Interval':
        """If self = X OR C, finding X from Y"""
        new_mask = (~constant) & self.physical_max
        new_value = self.known_value & new_mask
        return Interval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def xor_inverse(self, constant: int) -> 'Interval':
        """If self = X XOR C, finding X from Y"""
        new_mask = self.known_mask
        new_value = (self.known_value ^ constant) & new_mask
        # Pass full interval [0, max] and let _mask_to_interval prune it automatically
        return Interval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def cast_size(self, new_bit_width: int) -> 'Interval':
        return Interval(self.min_val, self.max_val, new_bit_width, known_mask=self.known_mask, known_value=self.known_value)

    def widen_to_top(self) -> 'Interval':
        return Interval(0, self.physical_max, self.bit_width)

class DisjointIntervalSet:
    """
    Manages bounded disjoint intervals to prevent State Explosion while retaining surgical precision.
    Uses K-Limit to force Convex Hull merging when fragmentation is too high.
    """
    def __init__(self, k_limit: int = 8):
        self.intervals: List[Interval] = []
        self.k_limit = k_limit
        
    def add(self, interval: Interval):
        if interval.min_val > interval.max_val:
            return # Dead path
            
        self.intervals.append(interval)
        if len(self.intervals) > self.k_limit:
            self.convex_hull()
            
    def convex_hull(self):
        """
        Emergency Brake: Merges all intervals into a single bounding Interval.
        """
        if not self.intervals:
            return
            
        new_min = min(i.min_val for i in self.intervals)
        new_max = max(i.max_val for i in self.intervals)
        bit_width = self.intervals[0].bit_width
        
        common_mask = self.intervals[0].known_mask
        common_value = self.intervals[0].known_value
        common_stride = self.intervals[0].stride
        common_offset = self.intervals[0].stride_offset
        
        for i in self.intervals[1:]:
            match_mask = ~(common_value ^ i.known_value) & i.physical_max
            common_mask = common_mask & i.known_mask & match_mask
            common_value = common_value & common_mask
            
            if i.stride != common_stride or i.stride_offset != common_offset:
                common_stride = 1
                common_offset = 0
                
        merged = Interval(new_min, new_max, bit_width, known_mask=common_mask, known_value=common_value, stride=common_stride, stride_offset=common_offset)
        self.intervals = [merged]
        
    def __repr__(self):
        return f"<DisjointIntervalSet K-Limit:{self.k_limit} Count:{len(self.intervals)}>"
