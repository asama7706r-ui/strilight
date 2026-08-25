from typing import List, Dict, Any, Optional, Union
import capstone
import capstone.x86


class Instruction:
    """
    Standard Instruction Representation for the Core Loop Compressor Engine.
    Natively integrates with the Capstone disassembler.
    """
    def __init__(
        self,
        address: int = 0,
        mnemonic: str = "",
        op_str: str = "",
        size: int = 4,
        tick: int = 0,
        regs_read: Optional[List[str]] = None,
        regs_write: Optional[List[str]] = None,
        mem_read: Optional[List[int]] = None,
        mem_write: Optional[List[int]] = None,
        operands: Optional[List[Dict[str, Any]]] = None,
        jump_taken: bool = False
    ):
        self.address = address
        self.mnemonic = mnemonic.lower().strip() if mnemonic else ""
        self.op_str = op_str.strip() if op_str else ""
        self.size = size
        self.tick = tick
        self.regs_read = list(regs_read) if regs_read else []
        self.regs_write = list(regs_write) if regs_write else []
        self.mem_read = list(mem_read) if mem_read else []
        self.mem_write = list(mem_write) if mem_write else []
        self.operands = list(operands) if operands else []
        self.jump_taken = jump_taken
        self.requested_flags: List[str] = []

    @classmethod
    def from_capstone(cls, cs_insn: capstone.CsInsn, tick: int = 0) -> 'Instruction':
        """Converts a Capstone CsInsn object directly into our standard Instruction schema."""
        regs_read = [cs_insn.reg_name(r) for r in cs_insn.regs_read]
        regs_write = []
        if hasattr(cs_insn, 'regs_access'):
            try:
                _, written = cs_insn.regs_access()
                regs_write = [cs_insn.reg_name(r) for r in written]
            except Exception:
                regs_write = [cs_insn.reg_name(r) for r in cs_insn.regs_write]
        else:
            regs_write = [cs_insn.reg_name(r) for r in cs_insn.regs_write]

        parsed_operands = []
        if hasattr(cs_insn, 'operands'):
            for op in cs_insn.operands:
                if op.type == capstone.x86.X86_OP_REG:
                    reg_name = cs_insn.reg_name(op.reg)
                    parsed_operands.append({'type': 'reg', 'value': reg_name, 'size': op.size})
                    if reg_name not in regs_read and len(parsed_operands) > 1:
                        regs_read.append(reg_name)
                    elif reg_name not in regs_write and len(parsed_operands) == 1:
                        regs_write.append(reg_name)
                elif op.type == capstone.x86.X86_OP_IMM:
                    parsed_operands.append({'type': 'imm', 'value': op.imm, 'size': op.size})
                elif op.type == capstone.x86.X86_OP_MEM:
                    base = cs_insn.reg_name(op.mem.base) if op.mem.base != 0 else None
                    index = cs_insn.reg_name(op.mem.index) if op.mem.index != 0 else None
                    scale = op.mem.scale
                    disp = op.mem.disp
                    parsed_operands.append({
                        'type': 'mem',
                        'size': op.size,
                        'base': base,
                        'index': index,
                        'scale': scale,
                        'disp': disp
                    })
                    if base and base not in regs_read:
                        regs_read.append(base)
                    if index and index not in regs_read:
                        regs_read.append(index)

        return cls(
            address=cs_insn.address,
            mnemonic=cs_insn.mnemonic,
            op_str=cs_insn.op_str,
            size=cs_insn.size,
            tick=tick,
            regs_read=regs_read,
            regs_write=regs_write,
            operands=parsed_operands
        )

    @classmethod
    def disassemble_bytes(cls, code_bytes: bytes, base_address: int = 0x1000, bit_mode: int = 64) -> List['Instruction']:
        """Disassembles raw x86 machine code bytes using Capstone into a list of Instructions."""
        mode = capstone.CS_MODE_64 if bit_mode == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        instructions = []
        for i, cs_insn in enumerate(md.disasm(code_bytes, base_address)):
            instructions.append(cls.from_capstone(cs_insn, tick=i + 1))
        return instructions

    def __repr__(self):
        return f"<Instruction 0x{self.address:x}: {self.mnemonic} {self.op_str}>"
