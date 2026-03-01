---
title: "Byte Flag — Flag Hidden in Raw PNG Bytes"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "forensics", "steganography"]
difficulty: "beginner"
summary: "Open the PNG in binary mode, locate the ASCII string 'flag' in the raw byte stream, and print every byte after that index — the flag is embedded verbatim in the file's binary content."
---

## The Challenge

A PNG file is given. The flag is not in the image visually, not in EXIF data, and not in any metadata field. It is literally concatenated as plain text somewhere inside the raw bytes of the file.

## Approach

If a flag string appears verbatim in a binary file you can find it with `str.find` on the raw file content. Reading the entire file in binary mode returns a `bytes` object; calling `.find("flag".encode())` returns the offset. Everything from that offset onwards is the flag until the terminal `}`.

No image library needed — this is a raw byte scan.

## Solution

```python
with open("flag.png", "rb") as flag:
    text = flag.read()
    index = text.find("flag".encode())
    for i in range(index, len(text)):
        print(chr(text[i]), end="")
```

`text.find("flag".encode())` locates the start. The loop prints characters in order from that byte onwards — the flag ends with `}` so the terminal character is visible in stdout.

## What I Learned

Before analysing an image with any library, running `strings` or doing a raw `find` for known patterns is always the first pass. Files carrying hidden ASCII content often carry it verbatim — no encoding, no encryption. `file.read()` then `.find()` is the fastest possible approach.
