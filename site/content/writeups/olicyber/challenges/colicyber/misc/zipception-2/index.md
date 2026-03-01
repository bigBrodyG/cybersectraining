---
title: "Zipception 2.0 — Nested ZIPs with Password Protection"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "forensics", "password-cracking", "rockyou", "python"]
difficulty: "intermediate"
summary: "100 nested password-protected ZIPs. Crack each archive's password against the rockyou wordlist, extract, delete, and repeat — 100 times."
---

## The Challenge

Same concept as Zipception, but each of the 100 nested archives is password-protected. You need to find the password for each layer, extract it, and move to the next.

## Approach

For each archive, run every word in `rockyou.txt` as a candidate password via `ZipFile.extractall(pwd=word)`. The `try/except` pattern exploits the fact that a wrong password raises an exception while the correct one extracts silently. Once extraction succeeds, delete the archive and proceed to the next one.

The loop runs from `100.zip` down to `1.zip`, with `i` indexing the current depth.

## Solution

```python
from zipfile import ZipFile
import os

def crack_password(password_list, obj):
	idx = 0
	with open(password_list, "rb") as file:
		for line in file:
			for word in line.split():
				try:
					idx += 1
					obj.extractall(pwd=word)
					print("La password è: ", word.decode())
					return True
				except:
					continue
	return False
wordlist = open("rockyou.txt", "rb")
cnt = len(list(wordlist))
for i in range(100):
    obj = ZipFile(f"{100-i}.zip")
    if crack_password("rockyou.txt", obj) == False:
        print("La wordlist non contiene la password corretta")
        break
    obj.close()
    os.remove(f"{100-i}.zip")
```

`crack_password` opens the wordlist in binary mode and tries every word. `obj.extractall(pwd=word)` raises `BadZipFile` or similar on a wrong password — the bare `except: continue` catches and skips it. When extraction succeeds the function returns `True` and the outer loop closes the ZipFile handle, removes it, and decrement to the next archive.

## What I Learned

Password-cracking inner loops in Python are slow by pure-Python standards — rockyou has ~14 million entries, so each layer may take seconds. The crux insight is that zipfile's exception-based API is the only portable way to validate a password without calling an external binary. For CTFs with passwords not in rockyou, checking `strings archive.zip` for hints or checking for hardcoded passwords in metadata is the fallback.
