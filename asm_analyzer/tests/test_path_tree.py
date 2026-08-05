import pytest
from asm_analyzer.engine.path_tree import PathTree, PathNode
from asm_analyzer.engine.tracker import TraceRecord

def test_path_node_init():
    record = TraceRecord(tick=5, address=0x1000, mnemonic="add", op_str="rax, rbx", size=3)
    node = PathNode(record)
    assert node.record == record
    assert node.ancestors == []
    assert str(node) == "<PathNode Tick:0005 add>"

def test_path_tree_operations():
    tree = PathTree()
    
    # Test Dead End
    target = "rax"
    tick = 10
    mem_hash = "fake_hash_123"
    reason = "Test Dead End"
    
    assert not tree.is_dead_end(target, tick, mem_hash)
    tree.mark_dead_end(target, tick, mem_hash, reason)
    assert tree.is_dead_end(target, tick, mem_hash)
    assert (target, tick, mem_hash) in tree.dead_ends
    
    # Test Caching
    slice_records = [TraceRecord(tick=i, address=0x1000+i, mnemonic="nop", op_str="", size=1) for i in range(3)]
    
    assert not tree.is_cached(target, tick)
    assert tree.get_cached_slice(target, tick) is None
    
    tree.cache_slice(target, tick, slice_records)
    
    assert tree.is_cached(target, tick)
    assert tree.get_cached_slice(target, tick) == slice_records

