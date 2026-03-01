---
title: "WordWang — Protocol Format Wrapping"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "misc", "protocol", "pwntools"]
difficulty: "beginner"
summary: "The server returns a word from a custom protocol. Wrap the response in the expected format — prepend '?', uppercase, append '!' — send it back, and the server returns the flag."
---

## The Challenge

The server expects a specific format for the echoed response. The raw server output is a word. The protocol demands it be wrapped: a leading `?`, the content uppercased, and a trailing `!`. Sending the word back through the right formatter earns the flag.

## Approach

Receive the server's prompt, strip the newline, uppercase the content, prepend `?` and append `!`. The server validates the format and returns the flag on the next line — trimmed to skip the first 34 characters (a fixed-length preamble before the actual flag value).

## Solution

```python
#!/usr/bin/env python3
from pwn import *

r = remote("wordwang.challs.olicyber.it", 10601)
r.recvline()
x = b'?' + r.recvline().replace(b'\n', b'').upper() + b'!'; print(x)
r.sendline(x)
print("\n\n"+ r.recvline()[34:].decode() + "\n\n")
```

`r.recvline()` discards the server's greeting. The second `recvline()` receives the word. Stripping `\n`, uppercasing, prepending `?` and appending `!` builds the protocol-correct response in one expression. `r.recvline()[34:]` skips the fixed preamble text and prints the flag.

## What I Learned

Custom-protocol challenges often require nothing more than reading the spec carefully and implementing the formatting rule. Pwntools `remote` with `recvline` / `sendline` is the fastest way to prototype a protocol client — the only real work is understanding what format the server expects back.
