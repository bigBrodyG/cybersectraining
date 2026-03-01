---
title: "2048 — Arithmetic Server Bot"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "automation", "pwntools"]
difficulty: "beginner"
summary: "Connect to a server that fires 2049 arithmetic challenges in Italian — SOMMA, DIFFERENZA, PRODOTTO, POTENZA, DIVISIONE_INTERA — and solve each one in under the timeout to receive the flag."
---

## The Challenge

The server sends an arithmetic expression labelled with an operation name in Italian and expects the correct answer. There are 2049 rounds. Doing them by hand is not an option.

## Approach

The response always contains the operation keyword and the operands as integers in the string. `re.findall(r'-?\d+\.?\d*', ...)` extracts all numbers including negatives. The operation name determines how to combine them. After 2049 correct answers the server returns the flag.

The five operations covered:
- `SOMMA` → sum of all extracted numbers  
- `DIFFERENZA` → first number minus second
- `PRODOTTO` → first times second
- `POTENZA` → first to the power of the second
- `DIVISIONE_INTERA` → integer division of first by second

`context.timeout = 1` keeps recv from hanging on a slow round.

## Solution

```python
# pip3 install pwntools
from pwn import remote, context
import re

r = remote("2048.challs.olicyber.it", 10007)
context.timeout = 1
sos = r.recv()
context.log_level = 'debug'

for i in range(2049):
    print(str(sos))
    if "DIVISIONE_INTERA" in str(sos):
        s = [int(s) for s in re.findall(r'-?\d+\.?\d*', str(sos))]
        t = s[0] // s[1]
        r.sendline(str(t))
    elif "SOMMA" in str(sos):
        s = [int(s) for s in re.findall(r'-?\d+\.?\d*', str(sos))]
        t = sum(s)
        r.sendline(str(t))
    elif "DIFFERENZA" in str(sos):
        s = [int(s) for s in re.findall(r'-?\d+\.?\d*', str(sos))]
        t = s[0] - s[1]
        r.sendline(str(t))
    elif "PRODOTTO" in str(sos):
        s = [int(s) for s in re.findall(r'-?\d+\.?\d*', str(sos))]
        t = s[0] * s[1]
        r.sendline(str(t))
    elif "POTENZA" in str(sos):
        s = [int(s) for s in re.findall(r'-?\d+\.?\d*', str(sos))]
        t = s[0] ** s[1]
        r.sendline(str(t))
    sos = r.recv()    
print(str(sos))
```

Each iteration reads a message, picks the branch for the current operation, extracts all integers from the string with a single regex pass, computes the answer, and sends it. After all 2049 iterations the final `r.recv()` contains the flag.

## What I Learned

Arithmetic servers are trivially automated once you pick the right operation dispatch pattern. The real risk is slow receives or a partial buffer — using `context.timeout` and re-entering `r.recv()` at the top of the loop handles both without complicated state management.
