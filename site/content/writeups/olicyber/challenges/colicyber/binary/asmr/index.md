---
title: "ASMR — Static XOR Reverse Engineering"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["reversing", "xor", "static-analysis"]
difficulty: "beginner"
summary: "Reverse a static XOR encryption: subtract flag bytes from key bytes position-by-position to recover the plaintext."
---

## The Challenge

The binary has a hardcoded encrypted flag and a hardcoded key. The encryption is a custom byte-level operation — not standard XOR but a subtraction: `key[i] - flag[i]` produces the plaintext character.

## Approach

Loading the binary in Ghidra or reading the decompiled output reveals two byte arrays: the ciphertext (`flag`) and the key (`key`). The encryption is `enc[i] = key[i] - plain[i]`, so decryption is `plain[i] = key[i] - enc[i]` — simple arithmetic reversal, no unknown values.

Both arrays are hardcoded, so no network interaction needed. Just read the values directly from the script.

## Solution

```python
from pwn import xor

flag = b"\x57WTEZfXhBBWVTPPhjUeuPCVW"
key = bytes.fromhex("BD C3 B5 AC D5 D9 CD DB B5  B7 C9 E8 B5 BD 81 C7 D6 89 C4 DB BC 77 DD D4".replace(" ",""))
print(len(flag), len(key))
for i in range(len(flag)):
    print(chr(key[i] - flag[i]), end="")
```

Each character of the flag is `key[i] - flag[i]` cast back to a printable character. The loop runs over every byte and prints the result directly.

## What I Learned

Static analysis challenges live and die on recognizing the operation. Once you see subtraction instead of XOR in the disassembly, the inversion is trivial arithmetic. The tool (`pwn.xor`) is imported but not used here — the actual operation is manual subtraction, showing it pays to read the decompilation carefully before defaulting to XOR.
