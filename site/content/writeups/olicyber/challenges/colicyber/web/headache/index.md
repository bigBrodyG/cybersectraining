---
title: "Headache — Flag in HTTP Response Header"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "http-headers", "python"]
difficulty: "beginner"
summary: "The flag is not in the response body — it is stored in a custom HTTP response header called 'Flag'. Use a HEAD request and read r.headers['Flag']."
---

## The Challenge

Visiting the site returns a blank or near-blank page. The flag is nowhere in the HTML. It is in the response headers.

## Approach

A HEAD request retrieves only headers without a response body. `requests.head` sends one. Reading `r.headers['Flag']` extracts the custom header value.

## Solution

```python
import requests
r = requests.head("http://headache.challs.olicyber.it/")
print(r.headers['Flag'])
```

Three lines. The flag is in the `Flag` header of the response. `.head()` is slightly cleaner than `.get()` here since we only care about headers, but both work.

## What I Learned

HTTP headers are often overlooked in manual browsing but are easily missed even in source-view. Always check response headers — `curl -I URL` or `requests.head().headers` — as a first-pass step on any web challenge where the page body looks empty. Custom headers (non-standard names) are a common CTF hiding spot.
