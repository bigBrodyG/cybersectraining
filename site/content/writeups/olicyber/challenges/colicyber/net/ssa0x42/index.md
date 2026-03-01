---
title: "SSA0x42 — XOR Key Recovery from Known-Plaintext PCAP Headers"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "forensics", "xor", "pcap", "crypto"]
difficulty: "intermediate"
summary: "Two known-plaintext byte sequences (k and l) from the PCAP header XOR to reveal the repeating key. XOR the encrypted flag block with that key to recover the plaintext."
---

## The Challenge

A PCAP file contains an encrypted transmission. The captures also leaks two fixed-format header values (`k` and `l`) whose relationship reveals the encryption key. The flag is a long hex blob (`f`) somewhere in the traffic, also XOR-encrypted with the same key.

## Approach

XOR encryption with a repeating key has a known-plaintext attack: if you know any two values that were XOR'd together (`a XOR b = c`), then knowing `a` gives you `b = a XOR c`. Here `k` and `l` are two known-format fields from the packet capture. XORing them gives the repeating key `r = k XOR l`. The flag `f` then decrypts as `f XOR (r * len(f)//len(r))` — tiling the 8-byte key across the full ciphertext length.

`f.split(b'\n\n')[1]` extracts the flag from the decrypted payload — the actual data lives after a double newline separator.

## Solution

```python
#!/usr/bin/env python3

def xor(a, b):
    assert type(a) == bytes
    assert type(a) == type(b)
    return bytes([x^y for x,y in zip(a,b)])

''' FILE DI PCAP '''
k = bytes.fromhex("704e34bbff99f3fe")
l = bytes.fromhex("6c00fad8ae0d6015")
f = bytes.fromhex("502fee1138e7e3846f3aaf4334b3b38a7a28ab113cf5e7826a2fe24330f3f685682bee5329a0a1c73c27a24322e1fccb6c27af0d3eb4e08e712cbc0271e4f6997a2bba173eb8b3877d6eaf1625fbe1826634a7023cfbb38a3c3ebc0c32f1f78e6e2be0695bf2ff8a7b35a6530ef8a7b46e7ffb1361a1a4df3011a3570ee5e6df7011fd3c3da0cc8f2c23fa0d35a0ac9616440a")
r = xor(l, k)

flag = xor(f, r * (len(f)//len(r)))
print(flag.split(b'\n\n')[1].decode())
```

`r = xor(l, k)` recovers the 8-byte repeating key. `r * (len(f)//len(r))` tiles it to match the length of `f` (integer multiplication on bytes repeats the sequence). The final XOR decrypts entirely in one line. The `split(b'\n\n')[1]` strips the packet header and leaves the flag.

## What I Learned

XOR with a repeating key is trivially broken with two known-plaintext samples of the same length as the key. Real stream cipher security requires at least ensuring the keystream never repeats. Any protocol that puts fixed-format headers in the ciphertext has handed the attacker a crib from which the full key can be derived.
