import pytest
from asm_analyzer.engine.stop_dict import STOP_FUNCTIONS

def test_stop_dict():
    assert isinstance(STOP_FUNCTIONS, dict)
    
    # Check for inputs
    assert "scanf" in STOP_FUNCTIONS
    assert STOP_FUNCTIONS["scanf"] == "input"
    
    # Check for outputs
    assert "printf" in STOP_FUNCTIONS
    assert STOP_FUNCTIONS["printf"] == "output"
    
    # Check for network
    assert "recv" in STOP_FUNCTIONS
    assert STOP_FUNCTIONS["recv"] == "network_input"

