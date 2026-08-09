import re

with open(r'd:\work_app\MyApp\asm_analyzer\tests\test_translator.py', 'r') as f:
    content = f.read()

# Add import at the top
if 'from asm_analyzer.tests.utils.record_factory import RecordFactory' not in content:
    content = content.replace('from asm_analyzer.engine.tracker import TraceRecord', 
                              'from asm_analyzer.engine.tracker import TraceRecord\nfrom asm_analyzer.tests.utils.record_factory import RecordFactory')

# Replace operands dictionaries with RecordFactory calls
# {'type': 'reg', 'value': 'rax', 'size': 8} -> RecordFactory.create_reg_operand('rax', 8)
content = re.sub(r"\{'type':\s*'reg',\s*'value':\s*'([^']*)',\s*'size':\s*(\d+)\}", r"RecordFactory.create_reg_operand('\1', \2)", content)

# {'type': 'imm', 'value': 5, 'size': 8} -> RecordFactory.create_imm_operand(5, 8)
content = re.sub(r"\{'type':\s*'imm',\s*'value':\s*([^,]+),\s*'size':\s*(\d+)\}", r"RecordFactory.create_imm_operand(\1, \2)", content)

# {'type': 'mem', 'disp': 0x5000, 'base': None, 'index': None, 'scale': 1, 'size': 8}
# -> RecordFactory.create_mem_operand(disp=0x5000, size=8, base=None, index=None, scale=1)
content = re.sub(r"\{'type':\s*'mem',\s*'disp':\s*([^,]+),\s*'base':\s*([^,]+),\s*'index':\s*([^,]+),\s*'scale':\s*([^,]+),\s*'size':\s*(\d+)\}", 
                 r"RecordFactory.create_mem_operand(disp=\1, size=\5, base=\2, index=\3, scale=\4)", content)

# We can keep TraceRecord(...), but then just assign .operands. The user liked RecordFactory.create_trace_record because it condensed it.
# However, my formatting will be:
# TraceRecord(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 5", size=5)
# to
# RecordFactory.create_trace_record(tick=1, address=0x1000, mnemonic="mov", op_str="rax, 5", size=5)
# Wait, actually, the user said they liked that it "cleans the code and reduces boilerplate", BUT the flaw was "Jules made lines too long".
# If I just replace dictionaries with RecordFactory.create_reg_operand, that already reduces boilerplate and prevents long lines.
# And changing TraceRecord(...) to RecordFactory.create_trace_record(...) is also good.
content = content.replace('TraceRecord(', 'RecordFactory.create_trace_record(')

with open(r'd:\work_app\MyApp\asm_analyzer\tests\test_translator.py', 'w') as f:
    f.write(content)

print("Refactored test_translator.py")
