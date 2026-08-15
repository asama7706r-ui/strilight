from typing import Dict, List, Tuple
from asm_analyzer.pruning.interval import Interval, DisjointIntervalSet

class StridedMemoryMap:
    """
    Abstract memory mapping using Strided Intervals for fast, safe loop execution.
    Implements 'Safe Approximation' for complex memory aliasing to maintain O(1) speed.
    """
    def __init__(self):
        # List of memory transactions: (address_interval, size_in_bytes, value_dset)
        self.writes: List[Tuple[Interval, int, DisjointIntervalSet]] = []
        
    def write(self, addr: Interval, size: int, value: DisjointIntervalSet):
        """Records an abstract write transaction."""
        self.writes.append((addr, size, value))
        
    def read(self, addr: Interval, size: int) -> DisjointIntervalSet:
        """
        Reads from the abstract memory.
        Uses Safe Approximation: 
        - If read exactly matches a recent write, returns the precise value.
        - If partial/complex overlap is detected, returns TOP (UNKNOWN) to prevent CPU hang.
        """
        # Search backwards (most recent write first)
        for w_addr, w_size, w_value in reversed(self.writes):
            # Check for physical intersection in the address space
            intersected = addr.intersect(w_addr)
            if intersected.min_val <= intersected.max_val:
                # Overlap detected! 
                # Check for exact match (Safe Approximation)
                if (addr.min_val == w_addr.min_val and 
                    addr.max_val == w_addr.max_val and 
                    size == w_size and 
                    addr.stride == w_addr.stride and 
                    addr.stride_offset == w_addr.stride_offset):
                    return w_value
                else:
                    # Complex partial overlap (e.g., read 1 byte from a 4-byte write)
                    # Safe approximation: return UNKNOWN (TOP)
                    dset = DisjointIntervalSet(k_limit=8)
                    dset.add(Interval(0, (1 << (size * 8)) - 1, size * 8))
                    return dset
                    
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
