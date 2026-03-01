---
title: "No Robots Here — Disallowed Path Discovery via robots.txt"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "robots-txt", "recon", "python"]
difficulty: "beginner"
summary: "robots.txt lists a Disallow path that the crawler is never supposed to visit. That path contains the flag."
---

## The Challenge

A static-looking website with no obvious input fields. The flag is hidden at an unlisted page that is intentionally excluded from search engine indexing.

## Approach

`robots.txt` is the standard file webmasters use to tell crawlers which paths to skip. Those Disallow entries are often the most interesting paths — they are hidden precisely because the developer did not want them indexed. Fetch `/robots.txt`, read the Disallow line, fetch that path.

## Solution

```python
import requests

site = "http://no-robots.challs.olicyber.it"
r = requests.get(f"{site}/robots.txt")
print(r.text)

r1 = requests.get(f"{site}/I77p0mhKjr.html")
print(r1.text)
```

`/robots.txt` returns something like:

```
User-agent: *
Disallow: /I77p0mhKjr.html
```

A direct GET to that path returns the flag in the page body.

## What I Learned

`robots.txt` should never be treated as an access control mechanism. It is public and tells anyone exactly what the developer wanted to keep private. Sensitive pages must be protected by authentication, not just excluded from crawlers.
