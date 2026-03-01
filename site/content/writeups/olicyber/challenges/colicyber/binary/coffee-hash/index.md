---
title: "Coffee Hash — Z3 Cyclic Hash Constraint Solving"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["reversing", "z3", "constraint-solving", "hash"]
difficulty: "intermediate"
summary: "Model a cyclic windowed hash as a system of linear equations over integer variables and solve it with Z3 to recover the flag."
---

## The Challenge

The binary applies a custom hash: the flag is broken into character positions, and for each position `i` the hash value is the sum of 7 consecutive characters (wrapping around cyclically). The 50 hash output values are given. The task is to invert this: find 50 character values that produce exactly those sums.

## Approach

This is a system of linear equations: each equation says `sum(flag[(i + k) % 50] for k in 0..6) == cfhash[i]`. With 50 equations and 50 unknowns, Z3 can solve it directly.

Declare 50 integer variables, add one constraint per hash value, call `check()`, extract the model. The output integers are ASCII codes, so cast them with `chr()`.

The wrapping is handled by `(i + e) % len(cfhash)` in the constraint loop.

## Solution

```python
from z3 import *

cfhash = "630:624:622:612:609:624:623:610:624:624:567:631:638:639:658:593:546:605:607:585:648:636:635:704:702:687:687:682:629:699:633:639:634:637:578:622:620:617:606:615:568:633:589:587:645:639:653:654:633:634".split(":")
for i in range(len(cfhash)):
    cfhash[i] = int(cfhash[i])
s = Solver()
flag = [Int("flag" + str(i)) for i in range(len(cfhash))]

for i in range(len(cfhash)):
    tot = 0
    for e in range(7):
        tot += flag[(i+e)%len(cfhash)]
    s.add(cfhash[i] == tot)
print(s.check())
m = s.model()
for i in flag:
    print(chr(m[i].as_long()), end="")
print("")
```

Z3 finds integer assignments satisfying all 50 sum constraints simultaneously. The model output for each variable is the ASCII code of the corresponding flag character.

## What I Learned

Cyclic windowed sums are a common pattern in custom hash functions. The moment you see a hash where `h[i] = sum(plain[i..i+k])` with cyclic indexing, you can set it up as a Z3 integer linear programming problem. Each output hash value becomes one equality constraint.
