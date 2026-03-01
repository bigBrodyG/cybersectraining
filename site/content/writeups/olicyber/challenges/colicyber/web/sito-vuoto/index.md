---
title: "Sito Vuoto — Flag Hidden in Page Source"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "source-review", "recon", "python"]
difficulty: "beginner"
summary: "The homepage appears empty, but the flag is embedded in an HTML comment or inside one of the linked static files (CSS or JS). Fetch each resource and grep for the flag pattern."
---

## The Challenge

The page renders blank. There are no visible elements, no forms, no functionality. The flag is somewhere in the served content.

## Approach

Check the raw HTML of the homepage for comments or hidden `<div>` elements, then check the loaded static assets: `/css/style.css` and `/js/script.js`. The flag string matches `flag{...}`.

## Solution

```python
import requests

site = "http://sito-vuoto.challs.olicyber.it"
pages = ["/", "/css/style.css", "/js/script.js"]

for page in pages:
    r = requests.get(site + page)
    for line in r.text.split("\n"):
        if "flag" in line.lower():
            print(f"[{page}]", line.strip())
```

Iterating the three resources and filtering for any line containing `flag` finds the hidden value. Which of the three files holds it depends on how the challenge is deployed — the script checks all three.

## What I Learned

"Security through obscurity" in web source files is no security at all. HTML comments, JS variables, and CSS custom properties are fully visible to anyone who views page source or uses DevTools. Never embed secrets in client-delivered content.
