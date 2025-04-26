#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host launchcode.pwn.ccit25.chals.havce.it --port 1342 launch_code
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'launch_code')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'launchcode.pwn.ccit25.chals.havce.it'
port = int(args.PORT or 1342)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No

from z3 import *

io = start_local()

io.recvuntil(b"nonce = ")

n_rand = int(io.recvline(), 10)

print(n_rand)

#io.recvuntil(b">>> ")

r9d, r10d, r11d, r12d = BitVecs('r9d r10d r11d r12d', 32)
s = Solver()
s.add(r11d - r12d + 1 == 0)
s.add((r10d / r11d) ^ 2 == 0)
s.add((r9d + r10d + n_rand) * 8 == 0)
print(s.check())
m = s.model()

sol1 = m[r9d].as_long()
sol2 = m[r10d].as_long()
sol3 = m[r11d].as_long()
sol4 = m[r12d].as_long()

print(sol1, sol2, sol3, sol4)

io.sendline(f"{hex(sol1)} {hex(sol2)} {hex(sol3)} {hex(sol4)}".encode())


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

