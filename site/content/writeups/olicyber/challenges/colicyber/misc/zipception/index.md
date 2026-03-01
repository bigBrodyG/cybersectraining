---
title: "Zipception — 3000 Nested ZIPs"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "forensics", "automation", "python"]
difficulty: "beginner"
summary: "A flag is hidden inside 3000 recursively nested ZIP archives. Loop backwards from flag3000.zip to flag1.zip, extracting and deleting each archive in turn until the innermost file is revealed."
---

## The Challenge

You receive `flag3000.zip`. Inside is `flag2999.zip`. Inside that, `flag2998.zip`. And so on until `flag1.zip` contains the actual file with the flag.

## Approach

Extract each archive into the working directory and immediately delete the spent ZIP. Loop from 3000 down to 1 using `abs(i - 3000)` to generate the correct filename at each step, since the range runs upward but the filenames decrease.

`zipfile.ZipFile` extracts everything to the directory, `os.remove` cleans up, and the loop continues. After 3000 iterations the inner file (not a ZIP) remains.

## Solution

```python
from zipfile import ZipFile
import os
for i in range(3000):
    with ZipFile("flag"+str(abs(i-3000))+".zip", "r") as zip:
        zip.extractall(os.path.dirname("Olicyber-WritesUp"))
    os.remove("flag"+str(abs(i-3000))+".zip")
```

`abs(i-3000)` maps `i=0` → `3000`, `i=1` → `2999`, ..., `i=2999` → `1`. `extractall` deposits the inner file into the current directory. `os.remove` deletes the now-spent outer archive so the directory stays clean.

## What I Learned

Nested archive challenges are solved with a simple reverse-indexed loop. The key insight is that `zipfile` does not modify the inner archive — it just copies it out — so the inner ZIP is untouched and ready for the next iteration. Keeping the directory clean with `os.remove` prevents confusion between old and new ZIPs.
