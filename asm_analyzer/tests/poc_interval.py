import sys
import os

# Ensure the root of the project is in sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from asm_analyzer.pruning.interval import Interval

def main():
    print("[*] AsmAnalyzer - Interval Pruning PoC")
    
    # 1. Forward Constraint Demo
    print("\n[+] 1. Initial State from Condition")
    # Imagine a condition: cmp AL, 20 ; jle (So AL is between 0 and 20)
    # Notice AL is an 8-bit register!
    al_interval = Interval(0, 20, bit_width=8)
    print(f"    AL Bounds from Condition: {al_interval}")
    
    # 2. Backward Tracing an Addition
    print("\n[+] 2. Backward Slicing an Addition")
    # The instruction before CMP was: add AL, 5
    # Inverse of ADD is SUB
    original_al = al_interval.add_inverse(5)
    print(f"    Original AL before 'add AL, 5': {original_al}")
    # Explanation:
    # 0 - 5 = -5. Since it's 8-bit, -5 wraps around to 251.
    # 20 - 5 = 15.
    # The interval becomes [251, 15] which mathematically represents [251...255] U [0...15] due to wrap-around.
    
    # 3. Size Casting (Truncation) Demo
    print("\n[+] 3. Physical Size Casting")
    # Imagine we have EAX (32-bit) with a huge range [500, 1000]
    eax_interval = Interval(500, 1000, bit_width=32)
    print(f"    EAX Original Bounds: {eax_interval}")
    
    # Now an instruction accesses AL instead (mov cl, al)
    # The interval gets physically truncated to 8-bit
    al_from_eax = eax_interval.cast_size(8)
    print(f"    After casting EAX to AL (8-bit): {al_from_eax}")
    # 500 & 0xFF = 244. 1000 & 0xFF = 232.
    # The hardware reality forces these exact bits.
    
if __name__ == "__main__":
    main()
