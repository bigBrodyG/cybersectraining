---
title: "Baity5 — Binary Exploitation"
date: 2025-03-01
categories: ["Olicyber"]
series: ["Territoriale 2025"]
tags: ["pwn", "binary-exploitation", "rop"]
difficulty: "intermediate"
summary: "Binary exploitation challenge from Territoriale 2025. Static analysis and attack strategy — no full exploit solved during competition."
---

## The Challenge

`baity5` is a binary-only challenge from Olicyber Territoriale 2025. The binary was distributed during the competition without source code. Based on the challenge family (the `baity` series in prior OliCyber editions typically involves progressively harder stack or heap primitives), this one likely involves a stack overflow or a format string vulnerability.

I didn't finish a working exploit script during the competition window, so this writeup is a placeholder documenting what I explored.

## Approach

Initial recon:

- `file baity5` → x86-64 ELF, dynamically linked
- `checksec baity5` → to be determined (I expect NX enabled, partial RELRO, likely no PIE based on the series)
- Running the binary: it prompts for input, seems to accept a name or buffer, and exits

The binary name "baity" suggests it's bait — there's probably a vulnerable read somewhere designed to look safe but isn't. The series naming convention at OliCyber usually escalates: `baity1` is trivially overflowable, `baity5` will have at least canary and PIE disabled but probably NX and some other mitigation to work around.

Without a solved exploit, I can't describe the complete chain. The likely path involves: finding the overflow offset with cyclic, checking for useful gadgets or a win function, and building a ROP chain or shellcode injection depending on protections.

## Solution

No complete solve script yet. This section will be updated once I revisit the binary.

Rough skeleton for when I come back to it:

```python
from pwn import *

elf = ELF('./baity5')
# p = process('./baity5')
p = remote('baity5.challs.territoriali.olicyber.it', PORT)

# TODO: find offset, leak canary if present, ROP to win / shell
offset = cyclic_find(0xdeadbeef)  # placeholder

payload = b'A' * offset
payload += p64(elf.symbols.get('win', 0x0))  # placeholder

p.sendlineafter(b'> ', payload)
p.interactive()
```

## What I Learned

Not every challenge gets solved during the competition. What matters is knowing why it didn't work and coming back with a clearer head — usually the blocker is a misjudged offset or a missed gadget.
