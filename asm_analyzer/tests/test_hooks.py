import sys
from unittest.mock import MagicMock

# Mock capstone
mock_capstone = MagicMock()
mock_capstone.CS_ARCH_X86 = 0
mock_capstone.CS_MODE_64 = 0
mock_cs_instance = MagicMock()
mock_capstone.Cs.return_value = mock_cs_instance
sys.modules['capstone'] = mock_capstone

mock_capstone_x86 = MagicMock()
mock_capstone_x86.X86_OP_REG = 1
mock_capstone_x86.X86_OP_MEM = 2
mock_capstone_x86.X86_OP_IMM = 3
sys.modules['capstone.x86'] = mock_capstone_x86

import pytest
from asm_analyzer.engine.hooks import setup_hooks
from asm_analyzer.engine.tracker import Tracker, TraceRecord

def test_setup_hooks():
    core = MagicMock()
    core.module_base = 0x1000
    core.module_size = 0x2000
    core.se = MagicMock()
    core.tracker = Tracker()
    core.tick_counter = 0
    core.current_mem_reads = []
    core.current_mem_writes = []

    setup_hooks(core)
    
    assert core.se.add_api_hook.call_count > 0
    assert core.se.add_code_hook.call_count == 1
    assert core.se.add_mem_read_hook.call_count == 1
    assert core.se.add_mem_write_hook.call_count == 1

def test_hook_code():
    core = MagicMock()
    core.module_base = 0x1000
    core.module_size = 0x2000
    core.se = MagicMock()
    core.se.emu.mem_read.return_value = b"\x90"
    core.tracker = MagicMock()
    core.tracker.trace_history = []
    core.tick_counter = 0
    core.current_mem_reads = []
    core.current_mem_writes = []

    setup_hooks(core)
    
    hook_code_func = core.se.add_code_hook.call_args[0][0]
    
    # Outside module
    hook_code_func(MagicMock(), 0x500, 1)
    assert core.tick_counter == 0
    
    # Inside module
    # Setup mock instruction
    mock_insn = MagicMock()
    mock_insn.address = 0x1500
    mock_insn.mnemonic = "nop"
    mock_insn.op_str = ""
    mock_insn.size = 1
    
    # Mock details
    mock_detail = MagicMock()
    mock_detail.regs_read = []
    mock_detail.regs_write = []
    
    # Needs to match capstone struct for operands iteration
    mock_insn.operands = []
    
    mock_cs_instance.disasm.return_value = [mock_insn]
    
    mock_emu = MagicMock()
    mock_emu.mem_read.return_value = b"\x90"
    hook_code_func(mock_emu, 0x1500, 1)
    
    assert core.tick_counter == 1
    assert core.tracker.add_trace.call_count == 1

def test_mem_hooks():
    core = MagicMock()
    core.module_base = 0x1000
    core.module_size = 0x2000
    core.se = MagicMock()
    core.tracker = MagicMock()
    core.tick_counter = 0
    core.current_mem_reads = []
    core.current_mem_writes = []

    setup_hooks(core)
    
    hook_mem_read_func = core.se.add_mem_read_hook.call_args[0][0]
    hook_mem_write_func = core.se.add_mem_write_hook.call_args[0][0]
    
    hook_mem_read_func(MagicMock(), 1, 0x5000, 4, 0)
    assert core.current_mem_reads == [0x5000]
    
    hook_mem_write_func(MagicMock(), 2, 0x6000, 4, 0x1234)
    assert core.current_mem_writes == [0x6000]
