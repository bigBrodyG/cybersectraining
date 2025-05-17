#!/usr/bin/env python3
from pwn import remote
import ast

# Connect to the remote service.
r = remote("mindblowing.challs.pascalctf.it", 420)

# Read until the menu prompt.
r.recvuntil("> ")
r.sendline("1")

# Choose index 2 (the flag sentence).
r.recvuntil("Gimme the index of a sentence:")
r.sendline("2")

# Increase the number of seeds to capture all bits.
n = 512
r.recvuntil("Gimme the number of seeds:")
r.sendline(str(n))

# Use powers-of-two as seeds.
results = []
for i in range(1, n+1):
    r.recvuntil(f"Seed of the number {i}: ")
    seed = 1 << (i-1)  # single bit mask
    r.sendline(str(seed))

# Read the output containing the result list.
result_line = r.recvline().strip().decode()
print("Received:", result_line)

# Parse the result list.
res_list = ast.literal_eval(result_line.split("Result: ")[1])

# Reconstruct the flag as an integer.
flag_int = 0
for i, val in enumerate(res_list):
    if val != 0:
        flag_int |= (1 << i)

# Convert the integer back to bytes.
# We use the seed count as an upper bound on the number of bits.
num_bytes = (n + 7) // 8
flag_bytes = flag_int.to_bytes(num_bytes, 'little').lstrip(b'\x00')

# If the flag appears reversed, try big-endian conversion.
if not flag_bytes.startswith(b'pascalCTF'):
    flag_bytes = flag_int.to_bytes(num_bytes, 'big').lstrip(b'\x00')

try:
    flag = flag_bytes.decode()
    print("Flag:", flag)
except UnicodeDecodeError:
    print("Flag (hex):", flag_bytes.hex())

# Optionally interact with the remote shell.
r.interactive()
