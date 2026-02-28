#!/usr/bin/env python3
from pwn import *

r = remote("wordwang.challs.olicyber.it", 10601)
r.recvline()
x = b'?' + r.recvline().replace(b'\n', b'').upper() + b'!'; print(x)
r.sendline(x)
print("\n\n"+ r.recvline()[34:].decode() + "\n\n")
