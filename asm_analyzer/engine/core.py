import os
# pyrefly: ignore [missing-import]
from qiling import Qiling
# pyrefly: ignore [missing-import]
from qiling.const import QL_VERBOSE, QL_OS, QL_ARCH
from asm_analyzer.engine.tracker import Tracker

class AnalyzerCore:
    def __init__(self, target_path: list[str] = None, rootfs: str = ".", arch: str = "x8664", os_type: str = "windows", code: bytes = None):
        """
        Initialize the core analyzer wrapping Qiling.
        
        :param target_path: List containing the path to the executable and any arguments.
        :param rootfs: Path to the rootfs directory required by Qiling.
        :param arch: Architecture (e.g., 'x8664').
        :param os_type: OS type (e.g., 'windows', 'linux').
        :param code: Optional shellcode bytes to run directly.
        """
        print(f"[+] Initializing AnalyzerCore...")
        
        if not os.path.exists(rootfs):
            os.makedirs(rootfs, exist_ok=True)
            
        # Determine arch and os type
        q_arch = QL_ARCH.X8664 if arch == "x8664" else QL_ARCH.X86
        q_os = QL_OS.WINDOWS if os_type == "windows" else QL_OS.LINUX
            
        # Initialize Qiling
        if code:
            self.ql = Qiling(code=code, rootfs=rootfs, archtype=q_arch, ostype=q_os, verbose=QL_VERBOSE.DEFAULT)
        else:
            self.ql = Qiling(target_path, rootfs, verbose=QL_VERBOSE.DEFAULT)
        
        # Initialize Tracker for Backward Slicing
        self.tracker = Tracker()
        
        try:
            self.ql.os.set_api("ExitProcess", lambda ql: ql.os.stop())
        except Exception:
            pass
        self.tick_counter = 0

    def get_memory_permissions_hash(self) -> str:
        """
        Creates a contextual footprint (hash) of the current memory permissions.
        This is crucial for preventing False-Dead-Ends in the PathTree if a previous
        path changed memory protections dynamically (e.g. via VirtualProtect).
        """
        import hashlib
        # get_mapinfo returns [(start, end, perms, info, ...)]
        mem_info = self.ql.mem.get_mapinfo()
        # We only care about start, end, and perms
        state_str = "".join(f"{m[0]:x}:{m[1]:x}:{m[2]}" for m in mem_info)
        return hashlib.md5(state_str.encode('utf-8')).hexdigest()

    def start(self):
        """Start the emulation."""
        print("[+] Starting emulation...")
        try:
            self.ql.run()
        except Exception as e:
            print(f"[-] Emulation stopped/failed: {e}")
        print(f"[+] Emulation finished. Total Ticks: {self.tick_counter}")
