---
title: "Bank Logic Bypass — Scientific Notation Bypasses Integer Validation"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["web", "logic-bug", "type-confusion", "validation-bypass", "python"]
difficulty: "beginner"
summary: "Submit a withdrawal amount in scientific notation to exploit loose type parsing and credit 1 billion to your balance."
---

## The Challenge

A bank web app lets you withdraw funds from your account. The frontend limits the `amount` field to 4 characters. The backend parses the amount but doesn't strictly validate the format — it accepts floats or scientific notation strings and converts them loosely. Sending `amount=1e9` bypasses the 4-character limit check (short string) and, if the backend treats it as `-1e9` (a negative withdrawal, which is a deposit) or the logic subtracts the parsed float and wraps around, you end up with a billion in your account. Then `/buy?item=flag` lets you purchase the flag.

## Approach

My first move was to just use the app normally. I logged in, saw my balance was small, tried to withdraw amounts and buy the flag — not enough money, obviously. Then I looked at the form: the amount field has a `maxlength="4"` attribute. That tells the server nothing; `maxlength` only works in the browser.

I tried submitting `9999` through Burp — still not enough. Then `-1` thinking it might add to the balance as a negative withdrawal — the server rejected it with a validation error.

Then I thought: what if I bypass the character limit with a *short* but numerically large value? Scientific notation — `1e9` is only 3 characters and means one billion. I sent it via the `/withdraw?amount=1e9` GET parameter directly (the script skips the form entirely) and the server just credited the account instead of blocking it.

From there, `/buy?item=flag` returned the flag in the URL as a `reward=` parameter.

## Solution

```python
import requests

BASE_URL = "http://ccit25.havce.it:31347/"

session = requests.Session()

# Step 1: Withdraw 1e9 (bypassing the 4-character limit restriction)
withdraw_response = session.get(f"{BASE_URL}/withdraw?amount=1e9")
print("Withdraw response:", withdraw_response.url)

# Step 2: Buy the flag
buy_response = session.get(f"{BASE_URL}/buy?item=flag")
print("Buy response:", buy_response.url)

# Step 3: Extract the flag from the response
if "reward=" in buy_response.url:
    flag = buy_response.url.split("reward=")[1]
    print("FLAG:", flag)
else:
    print("Flag not found, something went wrong.")
```

If the server expects a negative withdraw to credit the account, `-1e9` works. If the bug is on a different endpoint or requires positive `1e9`, adjust accordingly. Either way the pattern is: pass a scientific notation number short enough to evade the frontend character limit but large enough to overflow the balance check.

## What I Learned

Client-side validation is never security. A 4-character limit in HTML does nothing once you're sending raw HTTP requests. Backend validation has to check the parsed value's range and type, not just the string length. Scientific notation exploiting `parseFloat` or Python's `float()` conversion is a surprisingly common logic-bug vector.
