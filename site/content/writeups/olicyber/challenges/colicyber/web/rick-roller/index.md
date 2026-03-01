---
title: "Rick Roller — Flag Behind a Redirect"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "redirect", "python"]
difficulty: "beginner"
summary: "The /get_flag.php endpoint immediately redirects the browser to a Rick Astley video. Disabling redirect following in requests reveals the 302 response body which contains the flag."
---

## The Challenge

Visiting `/get_flag.php` in a browser redirects you to a well-known music video. The flag is in the response from `/get_flag.php` itself, before the redirect is followed.

## Approach

Browsers (and `requests` by default) follow HTTP 3xx redirects automatically. To see the response of the redirecting endpoint — before following — pass `allow_redirects=False`. The 302 response body contains the flag.

## Solution

```python
import requests

r = requests.get("http://roller.challs.olicyber.it/get_flag.php", allow_redirects=False)
print(r.text)
```

With `allow_redirects=False`, `requests` returns the raw 302 response. The flag is in `r.text`.

## What I Learned

HTTP redirects do not erase the response body of the redirecting page. Sensitive data in the body of a 302 is exposed to anyone who stops before following the redirect. Always check what the redirecting endpoint returns before the `Location` header is acted upon.
