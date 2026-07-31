import speakeasy
import json
import os

target_exe = r"D:\work_app\MyApp\crackme_boss.exe"

# 1. Load default config and apply custom overlay
config_path = os.path.join(os.path.dirname(speakeasy.__file__), 'configs', 'default.json')
with open(config_path, 'r') as f:
    custom_config = json.load(f)

custom_config["command_line"] = "crackme_boss.exe 300"
custom_config.setdefault("modules", {})["functions_always_exist"] = True

# 2. Initialize Speakeasy and load module
se = speakeasy.Speakeasy(config=custom_config)
module = se.load_module(target_exe)

# 3. Run emulation (Without our hook_entry, so it does the normal CRT init)
print("[+] Emulating with standard configuration...")
try:
    se.run_module(module, all_entrypoints=True)
except Exception as e:
    print(f"[-] Emulation error: {e}")

# 4. Generate and save the report
report = se.get_report()
with open("report_analysis.json", "w") as f:
    json.dump(report, f, indent=2)

print("[+] Report generated and saved to report_analysis.json")
