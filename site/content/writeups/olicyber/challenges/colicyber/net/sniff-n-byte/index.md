---
title: "Sniff N Byte — Decode Hardcoded Hex Flag"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "forensics", "encoding"]
difficulty: "beginner"
summary: "The flag is encoded as concatenated 0x-prefixed hex bytes embedded directly in the capture. Strip the prefixes, decode with bytes.fromhex, and print."
---

## The Challenge

A network capture contains the flag encoded as a sequence of `0x`-prefixed hex values. Sometimes flags are hidden in custom protocols or unusual packet fields — here it is literally in the packet data as a hex string once you strip the `0x` prefixes.

## Approach

Remove the `0x` prefix from each byte representation by replacing `"0x"` with `""`, then call `bytes.fromhex` on the resulting clean hex string.

## Solution

```python
s = "0x660x6c0x610x670x7b0x370x680x330x590x5f0x350x410x790x5f0x790x300x750x5f0x630x340x4e0x5f0x350x4e0x310x660x660x5f0x5e0x2d0x5e0x7d".replace("0x", "")
print(bytes.fromhex(s).decode())
```

`replace("0x", "")` strips all the `0x` prefixes at once, leaving a single clean hex string. `bytes.fromhex` decodes it to raw bytes. `.decode()` interprets those bytes as ASCII.

## What I Learned

Finding hex-encoded data in captures is often just a matter of noticing the `0x` pattern and running the three-step clean/decode/print pipeline. The `replace("0x", "")` trick works on concatenated prefixed hex sequences regardless of length.
