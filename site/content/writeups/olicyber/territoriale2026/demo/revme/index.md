---
title: "RevMe"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["rev", "reverse-engineering", "xor", "bit-rotation", "pwntools"]
difficulty: "beginner"
summary: "Reverse a three-step transformation (reverse + rotate + XOR) applied to a 36-byte target symbol to recover the flag."
---

## The Challenge

`revme` is an x86-64 ELF binary for reverse engineering. It contains a global symbol `target` holding 36 bytes of transformed data. The binary applies a series of transforms to a flag string and stores the result; your job is to invert those transforms and read the original.

## Approach

Opening the binary in a decompiler, the transformation on each byte at index `i` is:

1. XOR with `0x37`
2. Left-rotate by `(i % 8)` bits
3. Add `i` (mod 256)

Then the entire array is reversed before being stored as `target`.

To recover the flag, apply the inverse operations in reverse order:

1. **Reverse the array** back to original ordering
2. **Subtract `i`** (mod 256) from each byte
3. **Right-rotate by `(i % 8)` bits** (invert the left-rotate)
4. **XOR with `0x37`** (XOR is its own inverse)

pwntools' ELF parser makes reading named symbols from a binary trivial, so I didn't need to manually extract bytes from the binary in a hex editor.

## Solution

```python
#!/usr/bin/env python3
from pwn import *
import os

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

def solve():
    binary_path = '/home/giordi/Repos/cybersectraining/Territoriale/Binary/revme'
    exe = ELF(binary_path)
    target_addr = exe.symbols['target']
    target_data = list(exe.read(target_addr, 36))
    
    buf = target_data[:]
    buf.reverse()
    
    for i in range(36):
        buf[i] = (buf[i] - i) & 0xff
        shift = i % 8
        buf[i] = ((buf[i] >> shift) | (buf[i] << (8 - shift))) & 0xff
        buf[i] ^= 0x37
        
    flag_str = bytes(buf).decode('utf-8', errors='ignore')
    print(f"Flag found: {flag_str}")

if __name__ == "__main__":
    solve()

# flag{reverse_me_if_you_can_5c0e9b38}
```

`exe.symbols['target']` gives the virtual address of the symbol; `exe.read(addr, 36)` reads the 36 bytes from that offset in the binary file. The transforms are then applied in inverse order: first reverse the array (undoing the final storage reversal), then subtract `i`, then right-rotate by `i % 8`, then XOR with `0x37`.

The `ror` helper computes an 8-bit right-rotation: shift right by `n`, shift left by `8-n`, mask to 8 bits. Standard trick.

Running the script prints `flag{reverse_me_if_you_can_5c0e9b38}`.

## What I Learned

When the transforms are applied in sequence and then the array is reversed, you have to be careful about the order of inversion — you undo the reversal first, then apply the per-byte inverses in the same positional order the forward transforms used. Getting that wrong shifts all the indices by one and produces garbage.
