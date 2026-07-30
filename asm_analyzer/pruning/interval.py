from typing import Optional

class Interval:
    """
    Physical Hardware-Encoded Interval.
    Represents the mathematical bounds of a variable/register alongside its physical constraints.
    """
    def __init__(self, min_val: int, max_val: int, bit_width: int = 64, known_bits_mask: Optional[int] = None):
        self.bit_width = bit_width
        # Physical limit based on bit_width
        self.physical_max = (1 << bit_width) - 1
        
        # Apply physical truncation/wrap-around upon initialization
        self.min_val = min_val & self.physical_max
        self.max_val = max_val & self.physical_max
        
        # In some cases, wrap-around means max < min (e.g., [250, 5] on 8-bit). 
        # For this PoC, we will try to keep it normalized or mark it as 'Wrapped' if it gets too complex,
        # but standard modulo arithmetic on bounds handles the physical reality.
        
        self.known_bits_mask = known_bits_mask if known_bits_mask is not None else 0

    def __repr__(self):
        return f"<Interval [{self.min_val}, {self.max_val}] ({self.bit_width}-bit)>"

    def intersect(self, other: 'Interval') -> 'Interval':
        """Intersects this interval with another to narrow down possibilities."""
        # For a true intersection, they should be the same bit width, 
        # or we cast one to the other.
        assert self.bit_width == other.bit_width, "Cannot intersect intervals of different bit widths without casting."
        
        new_min = max(self.min_val, other.min_val)
        new_max = min(self.max_val, other.max_val)
        
        if new_min > new_max:
            # Conflict / Dead Path
            return Interval(0, 0, self.bit_width) # Should ideally raise a PathDeadEnd exception
            
        return Interval(new_min, new_max, self.bit_width)

    # =========================================================================
    # Inverse Operations (Backward Slicing Algebra)
    # =========================================================================

    def add_inverse(self, constant: int) -> 'Interval':
        """
        Inverse of ADD: If Y = X + C, and we know Y in [min, max],
        then X = Y - C.
        """
        # We subtract the constant from both bounds.
        # The '& self.physical_max' handles the physical underflow automatically.
        new_min = (self.min_val - constant) & self.physical_max
        new_max = (self.max_val - constant) & self.physical_max
        return Interval(new_min, new_max, self.bit_width)

    def sub_inverse(self, constant: int) -> 'Interval':
        """
        Inverse of SUB: If Y = X - C, then X = Y + C.
        """
        new_min = (self.min_val + constant) & self.physical_max
        new_max = (self.max_val + constant) & self.physical_max
        return Interval(new_min, new_max, self.bit_width)

    def cast_size(self, new_bit_width: int) -> 'Interval':
        """
        Simulates casting (e.g., mov AL, EAX or movzx RAX, AL).
        This forces a new physical wrap-around.
        """
        return Interval(self.min_val, self.max_val, new_bit_width)

    def widen_to_top(self) -> 'Interval':
        """
        Safe Widening: If an operation is too complex to invert (MBA obfuscation),
        we widen the interval to the maximum physical bounds (Top).
        """
        return Interval(0, self.physical_max, self.bit_width)
