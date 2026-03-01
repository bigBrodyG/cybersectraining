import subprocess
import re

# start server
proc = subprocess.Popen(["python3", "server.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

# interact
# it expects 1 or 2. we choose 2.
proc.stdin.write("2\n")
proc.stdin.flush()

# read output
out_lines = []
while True:
    line = proc.stdout.readline()
    out_lines.append(line)
    if "enter the signature for the message" in line:
        break

out_text = "".join(out_lines)
match = re.search(r'enter the signature for the message "(.*?)"', out_text)
if not match:
    print("Could not find message:", out_text)
    exit(1)

message = match.group(1)
print("Got message:", message)

# run forge
forge_proc = subprocess.Popen(["MAYO-C/build/apps/example_mayo", message], stdout=subprocess.PIPE, text=True)
sig_hex, _ = forge_proc.communicate()
sig_hex = sig_hex.strip()

print("Forged signature:", sig_hex[:64], "...")

proc.stdin.write(sig_hex + "\n")
proc.stdin.flush()

final_out = proc.stdout.read()
print("Final output:")
print(final_out)
