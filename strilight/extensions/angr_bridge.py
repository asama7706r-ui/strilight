"""
Angr CFG and Static Natural Loop Extractor Bridge for Strilight.
Connects angr's CFGFast and LoopFinder directly to Strilight's LoopBlock containers.
"""
from typing import List, Dict, Any, Optional, Union
import logging

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

from strilight.arch.instruction import Instruction
from strilight.arch.loop_compressor import LoopBlock

logger = logging.getLogger("strilight.extensions.angr_bridge")


class AngrBridge:
    """
    Automated Static Loop and CFG Extraction Bridge.
    Uses angr.analyses.CFGFast and angr.analyses.LoopFinder to extract natural loops
    from binary executables (PE/ELF) and packages them into Strilight LoopBlock containers.
    """
    def __init__(self, binary_path: str, auto_load_libs: bool = False):
        if not ANGR_AVAILABLE:
            raise ImportError(
                "angr is not installed. Please install it with `pip install angr` to use AngrBridge."
            )
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=auto_load_libs)
        self._cfg = None
        self._loop_finder = None

    @property
    def cfg(self):
        """Lazily generates and caches CFGFast."""
        if self._cfg is None:
            logger.info("Generating CFGFast with angr...")
            self._cfg = self.project.analyses.CFGFast(normalize=True)
        return self._cfg

    @property
    def loop_finder(self):
        """Lazily generates and caches LoopFinder."""
        if self._loop_finder is None:
            # Ensure CFG is built and stored in knowledge base first
            _ = self.cfg
            logger.info("Extracting natural loops via angr LoopFinder...")
            self._loop_finder = self.project.analyses.LoopFinder()
        return self._loop_finder

    def get_all_loops(self) -> List[Any]:
        """Returns all raw angr Loop objects found in the binary."""
        return list(self.loop_finder.loops)

    def extract_function_loops(self, func_name_or_addr: Union[str, int]) -> List[LoopBlock]:
        """
        Finds all natural loops within a specific function and converts them to LoopBlocks.
        """
        func = None
        if isinstance(func_name_or_addr, str):
            func = self.cfg.functions.function(name=func_name_or_addr)
        else:
            func = self.cfg.functions.function(addr=func_name_or_addr)

        if func is None:
            logger.warning(f"Function '{func_name_or_addr}' not found in CFG.")
            return []

        func_loops = [loop for loop in self.loop_finder.loops if loop.entry.addr in func.block_addrs_set]
        loop_blocks = []
        for loop in func_loops:
            block = self.convert_loop_to_loop_block(loop)
            if block:
                loop_blocks.append(block)
        return loop_blocks

    def convert_loop_to_loop_block(self, loop: Any, default_iterations: int = 1000) -> LoopBlock:
        """
        Converts an angr Loop object into a Strilight LoopBlock containing disassembled Instruction objects.
        """
        # Collect and sort basic block addresses within the loop body
        body_node_addrs = sorted(list({node.addr for node in loop.body_nodes}))
        instructions: List[Instruction] = []

        for node_addr in body_node_addrs:
            try:
                block_bytes = self.project.factory.block(node_addr).bytes
                node_insns = Instruction.disassemble_bytes(
                    block_bytes,
                    base_address=node_addr,
                    bit_mode=self.project.arch.bits
                )
                instructions.extend(node_insns)
            except Exception as e:
                logger.warning(f"Failed to disassemble block at {hex(node_addr)}: {e}")

        # Construct and return standard LoopBlock
        return LoopBlock(body=instructions, iterations=default_iterations)
