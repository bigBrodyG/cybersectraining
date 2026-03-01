---
title: "CrackMat — Z3 Per-Character Quadratic Equations"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["reversing", "z3", "constraint-solving"]
difficulty: "beginner"
summary: "Each flag character satisfies an independent quadratic equation in integer form; Z3 solves all 20 simultaneously to recover the flag."
---

## The Challenge

The binary validates the flag character by character: each byte `c` must satisfy `c² - k*c == -k²/4` for a per-position constant `k`. Equivalently, the equation has two roots — only one of them is a valid printable ASCII character.

## Approach

Looking at the constraints, each one is `flag[i]² - coeff[i] * flag[i] == constant[i]`. These are independent one-variable quadratic equations, so they have at most two integer solutions each. One will be a printable ASCII code, the other either negative or out of range.

Z3 handles this trivially: declare 20 `Int` variables, add 20 constraints, solve. The model gives the integer value for each character; cast to bytes with `.to_bytes(1, "little")` and decode.

## Solution

```python
from z3 import *

flag = [Int("flag" + str(i)) for i in range(20)]
s = Solver()
s.add(flag[0] * flag[0] - 204 * flag[0] == -10404)
s.add(flag[1] * flag[1] - 216 * flag[1] == -11664)
s.add(flag[2] * flag[2] - 194 * flag[2] == -9409)
s.add(flag[3] * flag[3] - 206 * flag[3] == -10609)
s.add(flag[4] * flag[4] - 246 * flag[4] == -15129)
s.add(flag[5] * flag[5] - 200 * flag[5] == -10000)
s.add(flag[6] * flag[6] - 102 * flag[6] == -2601)
s.add(flag[7] * flag[7] - 232 * flag[7] == -13456)
s.add(flag[8] * flag[8] - 202 * flag[8] == -10201)
s.add(flag[9] * flag[9] - 228 * flag[9] == -12996)
s.add(flag[10] * flag[10] - 218 * flag[10] == -11881)
s.add(flag[11] * flag[11] - 210 * flag[11] == -11025)
s.add(flag[12] * flag[12] - 220 * flag[12] == -12100)
s.add(flag[13] * flag[13] - 194 * flag[13] == -9409)
s.add(flag[14] * flag[14] - 220 * flag[14] == -12100)
s.add(flag[15] * flag[15] - 232 * flag[15] == -13456)
s.add(flag[16] * flag[16] - 202 * flag[16] == -10201)
s.add(flag[17] * flag[17] - 190 * flag[17] == -9025)
s.add(flag[18] * flag[18] - 96 * flag[18] == -2304)
s.add(flag[19] * flag[19] - 250 * flag[19] == -15625)
print(s.check())
m = s.model()
for i in flag:
    print(m[i].as_long().to_bytes(1, "little").decode(), end="")
```

Each constraint is `x² - kx + k²/4 == 0`, which factors as `(x - k/2)² == 0`, giving `x == k/2`. The constants in each equation encode half the ASCII value of the corresponding character — but Z3 solves it without needing to spot the pattern.

## What I Learned

When the binary validates each character independently with a polynomial equation, there's no need to reverse the math by hand. Z3 handles polynomial constraints natively. The key signal is independent per-character checks — if they don't mix characters, each variable is solvable in isolation.
