from typing import Dict, List, Tuple, Union
from strilight.pruning.interval import Interval, StridedInterval, DisjointIntervalSet

class StridedMemoryMap:
    """
    Abstract memory mapping using Strided Intervals for fast, safe loop execution.
    Implements 'Safe Approximation' and 'Bézout Modulo Congruence Non-Aliasing'
    (Notion Sections 3 & 8) to maintain O(1) mathematical speed and zero false aliasing.
    """
    def __init__(self):
        # List of memory transactions: (address_interval, size_in_bytes, value_dset)
        self.writes: List[Tuple[Union[Interval, StridedInterval], int, DisjointIntervalSet]] = []
        
    def write(self, addr: Union[Interval, StridedInterval], size: int, value: DisjointIntervalSet):
        """Records an abstract write transaction."""
        self.writes.append((addr, size, value))
        
    def read(self, addr: Union[Interval, StridedInterval], size: int) -> DisjointIntervalSet:
        """
        Reads from the abstract memory.
        Uses Bézout Modulo Congruence Non-Aliasing (Rule 8.b.1) and Must-Alias (Rule 8.b.2):
        - If proven Definite Non-Alias via gcd(s1, s2) or disjoint bounds: skip safely.
        - If read exactly matches a recent write (Must-Alias): returns the precise value.
        - If complex partial overlap is detected: returns TOP (UNKNOWN).
        """
        # Search backwards (most recent write first)
        for w_addr, w_size, w_value in reversed(self.writes):
            # 1. Modulo Congruence Non-Alias Test (Bézout GCD)
            if hasattr(addr, 'is_disjoint_modulo') and hasattr(w_addr, 'is_disjoint_modulo'):
                if addr.is_disjoint_modulo(w_addr):
                    continue  # Definite Non-Alias: No interference!
                    
            # 2. Must-Alias Test
            if hasattr(addr, 'is_must_alias') and hasattr(w_addr, 'is_must_alias'):
                if addr.is_must_alias(w_addr) and size == w_size:
                    return w_value
                    
            # 3. Fallback Intersection Check for Interval objects
            if hasattr(addr, 'intersect') and hasattr(w_addr, 'intersect'):
                intersected = addr.intersect(w_addr)
                if intersected.min_val <= intersected.max_val:
                    # Physical overlap detected
                    if (addr.min_val == w_addr.min_val and 
                        addr.max_val == w_addr.max_val and 
                        size == w_size and 
                        getattr(addr, 'stride', 1) == getattr(w_addr, 'stride', 1) and 
                        getattr(addr, 'stride_offset', 0) == getattr(w_addr, 'stride_offset', 0)):
                        return w_value
                    else:
                        # Complex partial overlap -> TOP (Safe Approximation)
                        dset = DisjointIntervalSet(k_limit=8)
                        dset.add(Interval(0, (1 << (size * 8)) - 1, size * 8))
                        return dset
                else:
                    continue
                    
        # Not found in writes, return TOP (Symbolic/Unknown initial memory)
        dset = DisjointIntervalSet(k_limit=8)
        dset.add(Interval(0, (1 << (size * 8)) - 1, size * 8))
        return dset


class AbstractState:
    """
    Represents the full hardware state in the Abstract Domain for the Loop Evaluator.
    """
    def __init__(self):
        # Registers are stored as DisjointIntervalSets for Surgical Precision + K-Limit
        self.registers: Dict[str, DisjointIntervalSet] = {}
        
        # Strided Memory to track loop array access
        self.memory = StridedMemoryMap()
        
        # Flags are stored as Interval (3-valued logic: 0, 1, or Unknown/TOP)
        # 1-bit width: [0, 0] means False, [1, 1] means True, [0, 1] means Unknown
        self.flags: Dict[str, Interval] = {}
        
    def get_register(self, reg_name: str, bit_width: int = 64) -> DisjointIntervalSet:
        if reg_name not in self.registers:
            dset = DisjointIntervalSet(k_limit=8)
            # Default to TOP (Unknown)
            dset.add(Interval(0, (1 << bit_width) - 1, bit_width))
            self.registers[reg_name] = dset
        return self.registers[reg_name]
        
    def set_register(self, reg_name: str, value: DisjointIntervalSet):
        self.registers[reg_name] = value

    def get_flag(self, flag_name: str) -> Interval:
        if flag_name not in self.flags:
            # TOP for 1 bit is [0, 1] (Unknown)
            self.flags[flag_name] = Interval(0, 1, 1)
        return self.flags[flag_name]
        
    def set_flag(self, flag_name: str, value: Interval):
        assert value.bit_width == 1, f"Flags must be 1-bit Intervals, got {value.bit_width}-bit"
        self.flags[flag_name] = value
