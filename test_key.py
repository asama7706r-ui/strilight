import subprocess

with open('crackme_boss.c', 'r') as f:
    code = f.read()

code = code.replace('int key = get_input();', 'int key = 2063206277; printf("res: %d\\n", check_key(key));')

with open('crackme_boss_test4.c', 'w') as f:
    f.write(code)

subprocess.run(["gcc", "crackme_boss_test4.c", "-o", "crackme_boss_test4.exe"], check=True)
res = subprocess.run(["crackme_boss_test4.exe"], capture_output=True, text=True)
print("Output:", res.stdout)
