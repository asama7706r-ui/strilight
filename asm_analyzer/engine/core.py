import os
import copy
import speakeasy
# pyrefly: ignore [missing-import]
import speakeasy.config as cfg
from asm_analyzer.engine.tracker import Tracker

class AnalyzerCore:
    def __init__(self, target_path: list[str] = None, rootfs: str = ".", arch: str = "x8664", os_type: str = "windows", code: bytes = None):
        """
        Initialize the core analyzer wrapping Speakeasy.
        
        :param target_path: List containing the path to the executable and any arguments.
        :param rootfs: Path to the rootfs directory (not actively used in Speakeasy but kept for interface).
        :param arch: Architecture (e.g., 'x8664').
        :param os_type: OS type (e.g., 'windows').
        :param code: Optional shellcode bytes to run directly.
        """
        print(f"[+] Initializing AnalyzerCore...")
        
        custom_config = copy.deepcopy(cfg.DEFAULT_CONFIG_DATA)
        if target_path:
            custom_config["command_line"] = " ".join(target_path)
            
        custom_config.setdefault("modules", {})["functions_always_exist"] = True
        self.se = speakeasy.Speakeasy(config=custom_config)
        
        if code:
            q_arch = 'amd64' if arch == "x8664" else 'x86'
            self.module = self.se.load_shellcode(code, arch=q_arch)
        else:
            self.module = self.se.load_module(target_path[0])
            
        self.module_base = self.module.base
        self.module_size = self.module.image_size
        
        # Initialize Tracker for Backward Slicing
        self.tracker = Tracker()
        self.tick_counter = 0
        self.current_mem_reads = []
        self.current_mem_writes = []

    def get_memory_permissions_hash(self) -> str:
        """
        Creates a contextual footprint (hash) of the current memory permissions.
        This is crucial for preventing False-Dead-Ends in the PathTree if a previous
        path changed memory protections dynamically (e.g. via VirtualProtect).
        """
        import hashlib
        state_str = ""
        try:
            # We only care about start, end, and perms from Unicorn's mem_regions
            mem_info = self.se.emu.mem_regions()
            state_str = "".join(f"{m[0]:x}:{m[1]:x}:{m[2]}" for m in mem_info)
        except Exception:
            pass
        return hashlib.md5(state_str.encode('utf-8')).hexdigest()

    def start(self):
        """Start the emulation."""
        print("[+] Starting emulation...")
        self.initial_regs = {}
        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            try:
                self.initial_regs[reg] = self.se.reg_read(reg)
            except Exception:
                pass
                
        try:
            self.se.run_module(self.module)
        except Exception as e:
            print(f"[-] Emulation stopped/failed: {e}")
        print(f"[+] Emulation finished. Total Ticks: {self.tick_counter}")
