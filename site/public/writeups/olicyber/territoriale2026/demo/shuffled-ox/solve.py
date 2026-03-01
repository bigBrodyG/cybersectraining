import os
import base64
from pwn import *

r = remote('10.45.1.2', 2002)

enc_flag_hex = r.recvline().decode().strip()
enc_flag = bytes.fromhex(enc_flag_hex)

inp = os.urandom(2000)
known_b85 = base64.b85encode(inp)

r.recvuntil(b'Hex message: ')
r.sendline(inp.hex().encode())

resp = r.recvline().decode().strip()
enc_inp_hex = resp.split('B85 message: ')[1]
enc_inp = bytes.fromhex(enc_inp_hex)

rev_map = {}
for i in range(len(known_b85)):
    rev_map[enc_inp[i]] = known_b85[i]

dec_b85 = bytearray()
for b in enc_flag:
    if b in rev_map:
        dec_b85.append(rev_map[b])
    else:
        print(f"Unknown char {b}")

flag = base64.b85decode(bytes(dec_b85)).decode('utf-8')
print("Flag:", flag)

# Add the flag as a comment
with open(__file__, 'a') as f:
    f.write(f"\n# {flag}\n")
