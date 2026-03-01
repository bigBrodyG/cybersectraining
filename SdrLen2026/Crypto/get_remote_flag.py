import socket
import re
import subprocess
import time

def recvuntil(sock, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = sock.recv(1)
        if not chunk: break
        data += chunk
    return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("mayo.challs.srdnlen.it", 1340))
recvuntil(s, b"choice: ")
s.sendall(b"2\n")

out = recvuntil(s, b"in hex): ").decode()
match = re.search(r'enter the signature for the message "(.*?)"', out)
if not match:
    print("Could not find message:", out)
    exit(1)

message = match.group(1)
print("Got message:", message)

# run forge
forge_proc = subprocess.Popen(["./example_mayo_2", message], cwd="Mayo/MAYO-C/build/apps", stdout=subprocess.PIPE, text=True)
sig_hex, _ = forge_proc.communicate()
sig_hex = sig_hex.strip()

# Some output could be before the hex string if we didn't remove printf
# Let's extract the longest hex string from sig_hex output
lines = sig_hex.split('\n')
real_sig = ""
for line in lines:
    if len(line) > 100:
        real_sig = line.strip()

print("Forged signature length:", len(real_sig))
print("Sending signature...")

s.sendall(real_sig.encode() + b"\n")

final_out = b""
s.settimeout(2.0)
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        final_out += chunk
except Exception:
    pass

print("Final output:")
print(final_out.decode(errors='ignore'))
s.close()
