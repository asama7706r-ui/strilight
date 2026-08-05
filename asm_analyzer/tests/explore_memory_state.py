import sys
import os

app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(app_dir, 'speakeasy'))
sys.path.append(app_dir)

from asm_analyzer.engine.core import AnalyzerCore
from asm_analyzer.engine.hooks import setup_hooks

def explore_memory():
    target_exe = r"D:\work_app\MyApp\crackme_boss.exe"
    
    print("[*] Initializing AnalyzerCore with Speakeasy backend...")
    core = AnalyzerCore(target_path=[target_exe, "5001"])
    setup_hooks(core)
    
    # سنقوم بإضافة خطاف (Hook) إضافي لمراقبة ما يراه المحاكي في الذاكرة
    def inspect_mem_read(emu, access, address, size, value):
        try:
            # قراءة القيمة الحقيقية من ذاكرة المحاكي أثناء التنفيذ
            actual_value = emu.mem_read(address, size)
            val_hex = actual_value.hex()
            # سنقوم بطباعة قراءات الذاكرة التي تقع في منطقة البيانات (Data/Rdata)
            if address > core.module_base + 0x1000:
                print(f"[Speakeasy Memory] Address: 0x{address:x} | Size: {size} bytes | Actual Value: 0x{val_hex}")
        except Exception as e:
            pass

    core.se.add_mem_read_hook(inspect_mem_read)
    
    print("[*] Running Emulator for a few instructions to inspect memory state...\n")
    
    # إيقاف المحاكي مبكراً بعد 150 تعليمة فقط لكي لا نغرق في المخرجات
    instruction_count = 0
    def stop_early(se, address, size):
        nonlocal instruction_count
        instruction_count += 1
        if instruction_count > 150:
            se.emu.emu_stop()
            
    core.se.add_code_hook(stop_early)
    
    try:
        core.start()
    except Exception as e:
        pass
        
    print("\n[*] ================= Analysis =================")
    print("As you can see, the Emulator (Speakeasy) perfectly knows the values in memory.")
    print("But let's look at what our Tracker recorded for one of these instructions:")
    
    # البحث عن تعليمة قامت بقراءة من الذاكرة في سجل المتتبع
    for record in core.tracker.trace_history:
        if record.mem_read:
            print(f"\nTick {record.tick}: {record.mnemonic} {record.op_str}")
            print(f"Tracker saved read addresses: {[hex(addr) for addr in record.mem_read]}")
            print("Notice that the VALUE is missing from the Tracker! It only knows the address.")
            break

if __name__ == '__main__':
    explore_memory()
