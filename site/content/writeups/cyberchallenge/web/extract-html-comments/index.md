---
title: "Extract HTML Comments"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["web", "html", "beautifulsoup", "steganography", "comments"]
difficulty: "beginner"
summary: "Use BeautifulSoup to extract HTML comment nodes from a page and reveal the hidden flag."
---

## The Challenge

An HTML file contains the flag hidden inside HTML comments (`<!-- ... -->`). The comments aren't visible in a rendered browser view, but they're present in the source. The task is to extract all comment nodes.

## Approach

The first thing I did was open the page in the browser — nothing visible. Then I checked the page source with Ctrl+U and immediately spotted `<!-- ... -->` blocks scattered through the HTML. The flag was split across several comments, so copying them by hand would have been annoying and error-prone.

BeautifulSoup has a `Comment` type that identifies comment nodes directly. A single `find_all` call with a lambda that checks `isinstance(text, Comment)` returns only them. The `.extract()` call removes each comment from the tree after printing it, though that step is only useful if you need to see the remaining HTML clean.

## Solution

```python
from bs4 import BeautifulSoup
from bs4 import Comment

with open("index.html") as f:
    soup = BeautifulSoup(f, "html.parser")

comments = soup.find_all(string=lambda text: isinstance(text, Comment))
for c in comments:
    print(c)
    print("===========")
    c.extract()
```

## What I Learned

HTML comment extraction is about three lines of BeautifulSoup. The broader lesson: anything in the HTML source that isn't visible to a user is visible to anyone reading the raw HTTP response. "Hidden in comments" is not a security mechanism — it's equivalent to leaving a note on a public bulletin board and hoping nobody reads the back.
