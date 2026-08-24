import logging
from typing import List, Dict, Tuple, Optional
from strilight.engine.tracker import TraceRecord, Descendant

logger = logging.getLogger("strilight.engine.path_tree")

class PathNode:
    def __init__(self, record: TraceRecord):
        self.record = record
        self.ancestors: List['PathNode'] = []
        
    def __repr__(self):
        return f"<PathNode Tick:{self.record.tick:04d} {self.record.mnemonic}>"

class PathTree:
    def __init__(self):
        # Maps (target_register_or_memory, tick) -> List of TraceRecord (The resolved slice)
        # This acts as our Verified Branch Cache (Memoization).
        self.memoized_slices: Dict[Tuple[str, int], List[TraceRecord]] = {}
        
        # We can also store the actual tree structure if needed for complex intersections
        self.root_nodes: List[PathNode] = []
        
        # Dead-End Cache: (target, tick, mem_permissions_hash) -> reason
        self.dead_ends: Dict[Tuple[str, int, str], str] = {}

    def mark_dead_end(self, target: str, tick: int, mem_hash: str, reason: str):
        """
        Marks a path as a Dead-End (e.g. Access Violation).
        The mem_hash ensures we don't falsely block a path if the memory permissions
        were changed (e.g. VirtualProtect) prior to reaching this point.
        """
        self.dead_ends[(target, tick, mem_hash)] = reason
        logger.debug("Node '%s' at Tick %s marked as DEAD! Reason: %s", target, tick, reason)

    def is_dead_end(self, target: str, tick: int, mem_hash: str) -> bool:
        """Checks if a specific path state has already been proven to crash."""
        return (target, tick, mem_hash) in self.dead_ends

    def is_cached(self, target: str, tick: int) -> bool:
        """Check if the exact path fingerprint (target at a specific tick) is already resolved."""
        return (target, tick) in self.memoized_slices

    def get_cached_slice(self, target: str, tick: int) -> Optional[List[TraceRecord]]:
        """Retrieve the pre-calculated backward slice."""
        if self.is_cached(target, tick):
            logger.debug("Found verified branch for '%s' at Tick %s!", target, tick)
            return self.memoized_slices[(target, tick)]
        return None

    def cache_slice(self, target: str, tick: int, slice_records: List[TraceRecord]):
        """
        Save the fully resolved backward slice into the memoization tree.
        The combination of 'target' and 'tick' guarantees an absolute identifier (Unique Fingerprint),
        preventing false similarity.
        """
        self.memoized_slices[(target, tick)] = slice_records
        logger.debug("Saved branch for '%s' at Tick %s (Length: %d)", target, tick, len(slice_records))
