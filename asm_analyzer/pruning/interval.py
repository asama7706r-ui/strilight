"""
Strided Interval Domain & Dual-Mask Reduced Product for x86_64 Binary Analysis.
Implements:
- Abstract Object S = s[m, M] with Circular Wrap-Around in Z / 2^w Z
- Transfer Functions with Bezout GCD: Add (+), Sub (-), Mul (*), Join (sqcup)
- Unary Operators: Neg (-x), Bitwise NOT (~x)
- Dual-Mask System (known_mask, known_value) for 3-Valued Logic Bitwise Precision
- Modulo Congruence Disjointness for Instant Memory Aliasing Pruning
"""

import math
from typing import Optional, List, Tuple


class StridedInterval:
    """
    Physical Hardware-Encoded Strided Interval in the Circular Domain S = s[m, M] (mod 2^w).
    Represents the mathematical set { x in Z/2^wZ | (x - m) mod 2^w <= (M - m) mod 2^w and (x - m) == 0 (mod s) }.
    """
    def __init__(
        self,
        min_val: int,
        max_val: int,
        bit_width: int = 64,
        known_mask: int = 0,
        known_value: int = 0,
        stride: int = 1,
        stride_offset: Optional[int] = None,
        is_circular: bool = False
    ):
        self.bit_width = bit_width
        self.physical_max = (1 << bit_width) - 1
        self.mod = 1 << bit_width
        
        # Modulo Stride (s >= 0)
        self.stride = stride
        
        # m (min_val) and M (max_val) normalized to 2^w
        self.min_val = min_val & self.physical_max
        self.max_val = max_val & self.physical_max
        
        # Stride offset relative to modulo ring
        if stride_offset is not None:
            self.stride_offset = stride_offset & self.physical_max
        else:
            self.stride_offset = (self.min_val % self.stride) if self.stride > 0 else self.min_val
            
        # Circularity flag: True if the interval wraps over zero (m > M)
        self.is_circular = is_circular or (self.min_val > self.max_val)
        
        # Dual-Mask System for 3-Valued Logic
        self.known_mask = known_mask & self.physical_max
        self.known_value = (known_value & self.known_mask) & self.physical_max
        
        # Normalize bounds and deduce masks
        if not self.is_circular:
            self._interval_to_mask()
            self._stride_to_mask()
            self._mask_to_interval()
            self._mask_to_stride()
        else:
            self._stride_to_mask()
            self._mask_to_interval_circular()

    # =========================================================================
    # Dual-Mask Bi-directional Conversions & Reduced Product
    # =========================================================================

    def _mask_to_interval(self):
        """Prunes linear min_val and max_val using the 3-Valued Logic mask."""
        if self.known_mask == 0:
            return
            
        # 1. Prune stride-based trailing known bits (if s = 2^k)
        if self.stride > 1 and (self.stride & (self.stride - 1)) == 0:
            k_mask = (self.stride - 1) & self.physical_max
            target_val = self.known_value & k_mask
            
            # Round min_val UP to next value satisfying target_val
            cur_min_rem = self.min_val & k_mask
            if cur_min_rem > target_val:
                self.min_val = (self.min_val & (~k_mask)) + (k_mask + 1) + target_val
            else:
                self.min_val = (self.min_val & (~k_mask)) | target_val
                
            # Round max_val DOWN to previous value satisfying target_val
            cur_max_rem = self.max_val & k_mask
            if cur_max_rem < target_val:
                if (self.max_val & (~k_mask)) >= (k_mask + 1):
                    self.max_val = (self.max_val & (~k_mask)) - (k_mask + 1) + target_val
                else:
                    self.max_val = (self.max_val & (~k_mask)) | target_val
            else:
                self.max_val = (self.max_val & (~k_mask)) | target_val
                
            self.min_val &= self.physical_max
            self.max_val &= self.physical_max
            
        else:
            unknown_mask = (~self.known_mask) & self.physical_max
            self.min_val = (self.min_val & unknown_mask) | self.known_value
            self.max_val = (self.max_val & unknown_mask) | self.known_value
        
        if self.min_val > self.max_val:
            self.min_val, self.max_val = min(self.min_val, self.max_val), max(self.min_val, self.max_val)

    def _mask_to_interval_circular(self):
        """Prunes circular interval using known bits without breaking wrap-around orientation."""
        if self.known_mask == 0:
            return
        unknown_mask = (~self.known_mask) & self.physical_max
        self.min_val = (self.min_val & unknown_mask) | self.known_value
        self.max_val = (self.max_val & unknown_mask) | self.known_value

    def _interval_to_mask(self):
        """Deduces common known bits from linear bounds."""
        if self.is_circular:
            return
            
        diff = self.min_val ^ self.max_val
        v = diff
        v |= v >> 1
        v |= v >> 2
        v |= v >> 4
        v |= v >> 8
        v |= v >> 16
        v |= v >> 32
        
        inferred_mask = (~v) & self.physical_max
        self.known_mask |= inferred_mask
        self.known_value = (self.known_value & (~inferred_mask)) | (self.min_val & inferred_mask)
        self.known_value &= self.known_mask

    def _stride_to_mask(self):
        """
        Stride to Mask Theorem (Reduced Product, Notion Section 4.a):
        If stride s = 2^k (power of 2), the lowest k bits are guaranteed fixed to (min_val mod 2^k).
        """
        if self.stride > 1 and (self.stride & (self.stride - 1)) == 0:
            k_mask = (self.stride - 1) & self.physical_max
            self.known_mask |= k_mask
            self.known_value = (self.known_value & (~k_mask)) | (self.min_val & k_mask)
            self.known_value &= self.known_mask

    def _mask_to_stride(self):
        """
        Deduces modulo stride from trailing known zeros/constants in known_mask.
        """
        if self.known_mask == 0:
            return
        tz = (self.known_mask + 1) & ~self.known_mask
        k_stride = tz & self.physical_max
        if k_stride > 1 and self.stride == 1:
            self.stride = k_stride
            self.stride_offset = self.min_val % self.stride if self.stride > 0 else self.min_val

    # =========================================================================
    # Containment & Length Properties
    # =========================================================================

    @property
    def length(self) -> int:
        """Calculates the circular span length (M - m) mod 2^w."""
        return (self.max_val - self.min_val) % self.mod

    @property
    def intervals(self) -> List['StridedInterval']:
        """Backward compatibility for algorithms expecting a collection of intervals."""
        return [self]

    def contains(self, x: int) -> bool:
        """
        Modular Distance Invariant:
        (x - m) mod 2^w <= (M - m) mod 2^w and (x - m) == 0 (mod s)
        """
        x_norm = x & self.physical_max
        dist = (x_norm - self.min_val) % self.mod
        
        if dist > self.length:
            return False
            
        if self.stride == 0:
            return dist == 0
        if self.stride == 1:
            return True
            
        return (dist % self.stride) == 0

    def __contains__(self, x: int) -> bool:
        return self.contains(x)

    def __repr__(self):
        stride_str = f" Stride:{self.stride}(+{self.stride_offset})" if self.stride > 1 else ""
        circ_str = " (Circular)" if self.is_circular else ""
        return f"<StridedInterval [{hex(self.min_val)}, {hex(self.max_val)}]{circ_str} Mask:{hex(self.known_mask)} Val:{hex(self.known_value)}{stride_str} ({self.bit_width}-bit)>"

    # =========================================================================
    # Abstract Transfer Functions with GCD
    # =========================================================================

    def intersect(self, other: 'StridedInterval') -> 'StridedInterval':
        """Intersects this interval with another using GCD congruence and bounding."""
        assert self.bit_width == other.bit_width, "Cannot intersect intervals of different bit widths."
        
        # Handle simple non-circular intersection
        if not self.is_circular and not other.is_circular:
            new_min = max(self.min_val, other.min_val)
            new_max = min(self.max_val, other.max_val)
            
            # Check Stride compatibility
            new_offset = 0
            if self.stride == other.stride and self.stride > 1:
                if self.stride_offset != other.stride_offset:
                    return StridedInterval(0, 0, self.bit_width, stride=1) # Dead path (Disjoint)
                new_stride = self.stride
                new_offset = self.stride_offset
            elif self.stride > 1 and other.stride == 1:
                new_stride = self.stride
                new_offset = self.stride_offset
            elif other.stride > 1 and self.stride == 1:
                new_stride = other.stride
                new_offset = other.stride_offset
            else:
                g = math.gcd(self.stride, other.stride)
                if g > 1 and (self.stride_offset % g) != (other.stride_offset % g):
                    return StridedInterval(0, 0, self.bit_width, stride=1)
                new_stride = g
                new_offset = self.stride_offset % g if g > 0 else 0
                
            new_mask = self.known_mask | other.known_mask
            new_value = (self.known_value | other.known_value) & new_mask
            
            if new_min > new_max:
                return StridedInterval(0, 0, self.bit_width, stride=1) # Dead path
                
            return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride, stride_offset=new_offset)
            
        # General Circular Intersection
        # Check modular congruence disjointness first
        g = math.gcd(self.stride, other.stride)
        if g > 1 and ((self.stride_offset % g) != (other.stride_offset % g)):
            return StridedInterval(0, 0, self.bit_width, stride=1)
            
        # Fallback to dual-mask intersection
        new_mask = self.known_mask | other.known_mask
        new_value = (self.known_value | other.known_value) & new_mask
        return StridedInterval(self.min_val, self.max_val, self.bit_width, known_mask=new_mask, known_value=new_value, stride=g)

    def join(self, other: 'StridedInterval') -> 'StridedInterval':
        """
        Abstract Join (sqcup^#) with GCD bridge (Notion Section 3.a):
        m_new = min(m1, m2), M_new = max(M1, M2), s_new = gcd(s1, s2, |m1 - m2|)
        Ensures strict commutativity and minimal convex hull.
        """
        assert self.bit_width == other.bit_width, "Cannot join intervals of different bit widths."
        
        # Combined known mask
        match_mask = ~(self.known_value ^ other.known_value) & self.physical_max
        new_mask = self.known_mask & other.known_mask & match_mask
        new_value = self.known_value & new_mask
        
        # 1. Linear Non-Circular Case
        if not self.is_circular and not other.is_circular:
            new_min = min(self.min_val, other.min_val)
            new_max = max(self.max_val, other.max_val)
            diff = abs(self.min_val - other.min_val)
            new_stride = math.gcd(self.stride, math.gcd(other.stride, diff))
            
            return StridedInterval(
                new_min, new_max, self.bit_width,
                known_mask=new_mask, known_value=new_value,
                stride=new_stride, is_circular=False
            )
            
        # 2. Circular / Wrapping Case: Compare both orientations to pick minimal envelope
        dist_fwd = (other.min_val - self.min_val) % self.mod
        len_fwd = max(self.length, dist_fwd + other.length)
        
        dist_rev = (self.min_val - other.min_val) % self.mod
        len_rev = max(other.length, dist_rev + self.length)
        
        if len_fwd <= len_rev:
            new_stride = math.gcd(self.stride, math.gcd(other.stride, dist_fwd))
            new_min = self.min_val
            new_len = len_fwd
        else:
            new_stride = math.gcd(self.stride, math.gcd(other.stride, dist_rev))
            new_min = other.min_val
            new_len = len_rev
            
        new_max = (new_min + new_len) % self.mod
        is_circ = (new_min > new_max) or (new_len >= self.mod)
        if new_len >= self.mod:
            new_min, new_max = 0, self.physical_max
            is_circ = False
            
        return StridedInterval(
            new_min, new_max, self.bit_width,
            known_mask=new_mask, known_value=new_value,
            stride=new_stride, is_circular=is_circ
        )

    def add(self, other: 'StridedInterval') -> 'StridedInterval':
        """
        Abstract Addition (oplus^#):
        s_new = gcd(s1, s2)
        m_new = (m1 + m2) mod 2^w
        M_new = (M1 + M2) mod 2^w
        """
        assert self.bit_width == other.bit_width, "Cannot add intervals of different bit widths."
        
        new_stride = math.gcd(self.stride, other.stride)
        new_min = (self.min_val + other.min_val) % self.mod
        new_max = (self.max_val + other.max_val) % self.mod
        
        # Dual-mask addition approximation
        new_mask = 0
        new_value = 0
        if self.known_mask == self.physical_max and other.known_mask == other.physical_max:
            new_mask = self.physical_max
            new_value = (self.known_value + other.known_value) & self.physical_max
            
        total_len = self.length + other.length
        is_circ = (new_min > new_max) or (total_len >= self.mod)
        if total_len >= self.mod:
            new_min, new_max = 0, self.physical_max
            is_circ = False
            
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride, is_circular=is_circ)

    def sub(self, other: 'StridedInterval') -> 'StridedInterval':
        """
        Abstract Subtraction:
        s_new = gcd(s1, s2)
        m_new = (m1 - M2) mod 2^w
        M_new = (M1 - m2) mod 2^w
        """
        assert self.bit_width == other.bit_width, "Cannot subtract intervals of different bit widths."
        
        new_stride = math.gcd(self.stride, other.stride)
        new_min = (self.min_val - other.max_val) % self.mod
        new_max = (self.max_val - other.min_val) % self.mod
        
        new_mask = 0
        new_value = 0
        if self.known_mask == self.physical_max and other.known_mask == other.physical_max:
            new_mask = self.physical_max
            new_value = (self.known_value - other.known_value) & self.physical_max
            
        total_len = self.length + other.length
        is_circ = (new_min > new_max) or (total_len >= self.mod)
        if total_len >= self.mod:
            new_min, new_max = 0, self.physical_max
            is_circ = False
            
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride, is_circular=is_circ)

    def mul(self, other: 'StridedInterval') -> 'StridedInterval':
        """
        Abstract Multiplication (otimes^#) (Notion Section 2.b):
        m_new = m1 * m2, M_new = M1 * M2
        s_new = gcd(m1*s2, m2*s1, s1*s2)
        """
        assert self.bit_width == other.bit_width, "Cannot multiply intervals of different bit widths."
        
        # Stride transfer function
        new_stride = math.gcd(
            self.min_val * other.stride,
            math.gcd(other.min_val * self.stride, self.stride * other.stride)
        )
        if new_stride == 0 and (self.stride > 0 or other.stride > 0):
            new_stride = max(self.stride, other.stride)
            
        new_min = (self.min_val * other.min_val) % self.mod
        new_max = (self.max_val * other.max_val) % self.mod
        
        new_mask = 0
        new_value = 0
        if self.known_mask == self.physical_max and other.known_mask == other.physical_max:
            new_mask = self.physical_max
            new_value = (self.known_value * other.known_value) & self.physical_max
            
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride)

    def neg(self) -> 'StridedInterval':
        """Two's complement negation (-x mod 2^w): Inverts bounds with step preserved."""
        new_min = (-self.max_val) % self.mod
        new_max = (-self.min_val) % self.mod
        return StridedInterval(new_min, new_max, self.bit_width, stride=self.stride, is_circular=self.is_circular)

    def bitwise_not(self) -> 'StridedInterval':
        """Bitwise NOT (~x mod 2^w): Inverts bounds with step preserved."""
        new_min = (~self.max_val) % self.mod
        new_max = (~self.min_val) % self.mod
        new_mask = self.known_mask
        new_value = (~self.known_value) & new_mask
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=self.stride, is_circular=self.is_circular)

    def bitwise_and(self, other: 'StridedInterval') -> 'StridedInterval':
        """Dual-Mask precision for AND with stride inference."""
        assert self.bit_width == other.bit_width
        known_zeros_self = self.known_mask & (~self.known_value)
        known_zeros_other = other.known_mask & (~other.known_value)
        known_ones_self = self.known_mask & self.known_value
        known_ones_other = other.known_mask & other.known_value
        
        new_known_zeros = (known_zeros_self | known_zeros_other) & self.physical_max
        new_known_ones = (known_ones_self & known_ones_other) & self.physical_max
        new_mask = new_known_zeros | new_known_ones
        new_value = new_known_ones
        
        new_max = min(self.max_val, other.max_val)
        new_min = 0
        
        # Stride preservation if masking low bits
        new_stride = math.gcd(self.stride, other.stride)
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride)

    def bitwise_or(self, other: 'StridedInterval') -> 'StridedInterval':
        assert self.bit_width == other.bit_width
        known_ones_self = self.known_mask & self.known_value
        known_ones_other = other.known_mask & other.known_value
        known_zeros_self = self.known_mask & (~self.known_value)
        known_zeros_other = other.known_mask & (~other.known_value)
        
        new_known_ones = (known_ones_self | known_ones_other) & self.physical_max
        new_known_zeros = (known_zeros_self & known_zeros_other) & self.physical_max
        new_mask = new_known_ones | new_known_zeros
        new_value = new_known_ones
        
        new_min = max(self.min_val, other.min_val)
        new_max = self.physical_max
        new_stride = math.gcd(self.stride, other.stride)
        return StridedInterval(new_min, new_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride)

    def bitwise_xor(self, other: 'StridedInterval') -> 'StridedInterval':
        assert self.bit_width == other.bit_width
        new_mask = self.known_mask & other.known_mask
        new_value = (self.known_value ^ other.known_value) & new_mask
        new_stride = math.gcd(self.stride, other.stride)
        return StridedInterval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value, stride=new_stride)

    # =========================================================================
    # Memory Aliasing & Disjointness Tests
    # =========================================================================

    def is_disjoint_modulo(self, other: 'StridedInterval') -> bool:
        """
        Modulo Congruence Non-Alias Test (Aliasing Rule 1):
        Returns True if intervals are guaranteed to be 100% disjoint (Non-Alias).
        """
        assert self.bit_width == other.bit_width
        g = math.gcd(self.stride, other.stride)
        
        # 1. Congruence Test: m1 != m2 (mod gcd(s1, s2))
        if g > 1 and ((self.min_val % g) != (other.min_val % g)):
            return True
            
        # 2. Linear Non-Overlap Test
        if not self.is_circular and not other.is_circular:
            if self.max_val < other.min_val or other.max_val < self.min_val:
                return True
                
        return False

    def is_definite_non_alias(self, other: 'StridedInterval') -> bool:
        """Aliasing Rule 1: Definite Non-Alias."""
        return self.is_disjoint_modulo(other)

    def is_must_alias(self, other: 'StridedInterval') -> bool:
        """
        Aliasing Rule 2 (Must-Alias, Notion Section 8.b):
        Returns True if intervals are guaranteed 100% identical in origin, bounds, and stride.
        """
        return (
            self.bit_width == other.bit_width
            and self.min_val == other.min_val
            and self.max_val == other.max_val
            and self.stride == other.stride
            and self.is_circular == other.is_circular
        )

    def congruence_test(self, target: int) -> bool:
        """Instant Pruning: Target = State_0 (mod s) (Notion Section 3.b)"""
        target_norm = target & self.physical_max
        if self.stride == 0:
            return target_norm == self.min_val
        if self.stride == 1:
            return self.contains(target_norm)
        return (target_norm % self.stride) == (self.min_val % self.stride)

    # =========================================================================
    # Backward Slicing Inverses & Sub-register Helpers
    # =========================================================================

    def add_inverse(self, constant: int) -> 'StridedInterval':
        new_min = (self.min_val - constant) % self.mod
        new_max = (self.max_val - constant) % self.mod
        return StridedInterval(new_min, new_max, self.bit_width, stride=self.stride, is_circular=self.is_circular)

    def sub_inverse(self, constant: int) -> 'StridedInterval':
        new_min = (self.min_val + constant) % self.mod
        new_max = (self.max_val + constant) % self.mod
        return StridedInterval(new_min, new_max, self.bit_width, stride=self.stride, is_circular=self.is_circular)

    def and_inverse(self, constant: int) -> 'StridedInterval':
        new_mask = constant & self.physical_max
        new_value = self.known_value & new_mask
        return StridedInterval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def or_inverse(self, constant: int) -> 'StridedInterval':
        new_mask = (~constant) & self.physical_max
        new_value = self.known_value & new_mask
        return StridedInterval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def xor_inverse(self, constant: int) -> 'StridedInterval':
        new_mask = self.known_mask
        new_value = (self.known_value ^ constant) & new_mask
        return StridedInterval(0, self.physical_max, self.bit_width, known_mask=new_mask, known_value=new_value)

    def zero_extend(self, src_bit_width: int, dst_bit_width: int = 64) -> 'StridedInterval':
        """
        x86_64 Sub-register Physics (Notion Section 4.b):
        32-bit writes zero-extend to 64-bit and wipe the upper 32 bits to 0.
        """
        src_mask = (1 << src_bit_width) - 1
        dst_mask = (1 << dst_bit_width) - 1
        new_min = self.min_val & src_mask
        new_max = self.max_val & src_mask
        if new_min > new_max:
            new_min, new_max = min(new_min, new_max), max(new_min, new_max)
            
        upper_zeros_mask = (dst_mask ^ src_mask) & dst_mask
        new_mask = (self.known_mask & src_mask) | upper_zeros_mask
        new_value = self.known_value & src_mask
        
        return StridedInterval(
            min_val=new_min,
            max_val=new_max,
            bit_width=dst_bit_width,
            known_mask=new_mask,
            known_value=new_value,
            stride=self.stride,
            is_circular=False
        )

    def blend(self, sub_interval: 'StridedInterval', bit_mask: int) -> 'StridedInterval':
        """
        x86_64 Sub-register Physics (Notion Section 4.b):
        8-bit / 16-bit writes blend into the base 64-bit register, preserving upper bits.
        """
        keep_mask = (~bit_mask) & self.physical_max
        sub_mask = bit_mask & self.physical_max
        
        new_mask = (self.known_mask & keep_mask) | (sub_interval.known_mask & sub_mask)
        new_value = (self.known_value & keep_mask) | (sub_interval.known_value & sub_mask)
        
        new_min = (self.min_val & keep_mask) | (sub_interval.min_val & sub_mask)
        new_max = (self.max_val & keep_mask) | (sub_interval.max_val & sub_mask)
        if new_min > new_max:
            new_min, new_max = min(new_min, new_max), max(new_min, new_max)
            
        return StridedInterval(
            min_val=new_min,
            max_val=new_max,
            bit_width=self.bit_width,
            known_mask=new_mask,
            known_value=new_value,
            stride=1,
            is_circular=False
        )

    def cast_size(self, new_bit_width: int) -> 'StridedInterval':
        return StridedInterval(self.min_val, self.max_val, new_bit_width, known_mask=self.known_mask, known_value=self.known_value, stride=self.stride)

    def widen_to_top(self) -> 'StridedInterval':
        return StridedInterval(0, self.physical_max, self.bit_width, stride=1)


# ==============================================================================
# Backward Compatibility Alias & Disjoint Set
# ==============================================================================

# Alias Interval to StridedInterval so all existing code seamlessly uses StridedInterval
Interval = StridedInterval


class DisjointIntervalSet:
    """
    Manages intervals with K-Limit using the GCD Join rule (sqcup^#) to avoid State Explosion.
    """
    def __init__(self, k_limit: int = 8):
        self.intervals: List[StridedInterval] = []
        self.k_limit = k_limit

    def add(self, interval: StridedInterval):
        if not interval.is_circular and interval.min_val > interval.max_val:
            return  # Dead path
            
        self.intervals.append(interval)
        if len(self.intervals) > self.k_limit:
            self.convex_hull()

    def convex_hull(self):
        """Merges all intervals using the Strided Join rule."""
        if not self.intervals:
            return
            
        merged = self.intervals[0]
        for i in self.intervals[1:]:
            merged = merged.join(i)
            
        self.intervals = [merged]

    def __repr__(self):
        return f"<DisjointIntervalSet K-Limit:{self.k_limit} Count:{len(self.intervals)}>"
