from asm_analyzer.engine.tracker import TraceRecord

class RecordFactory:
    @staticmethod
    def create_trace_record(tick, address, mnemonic, op_str, size=1, operands=None, mem_read=None, mem_write=None, regs_read=None, regs_write=None, requested_flags=None, jump_taken=None):
        record = TraceRecord(tick=tick, address=address, size=size, mnemonic=mnemonic, op_str=op_str)
        
        if operands is not None:
            record.operands = operands
        else:
            record.operands = []
            
        if mem_read is not None:
            record.mem_read = mem_read
        if mem_write is not None:
            record.mem_write = mem_write
        if regs_read is not None:
            record.regs_read = regs_read
        if regs_write is not None:
            record.regs_write = regs_write
        if requested_flags is not None:
            record.requested_flags = requested_flags
        if jump_taken is not None:
            record.jump_taken = jump_taken
            
        return record

    @staticmethod
    def create_reg_operand(value, size):
        return {'type': 'reg', 'value': value, 'size': size}

    @staticmethod
    def create_imm_operand(value, size):
        return {'type': 'imm', 'value': value, 'size': size}

    @staticmethod
    def create_mem_operand(disp, size, base=None, index=None, scale=1):
        return {'type': 'mem', 'base': base, 'index': index, 'scale': scale, 'disp': disp, 'size': size}
