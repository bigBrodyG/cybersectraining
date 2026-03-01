---
title: "Math Solver"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["web", "automation", "requests", "python", "session"]
difficulty: "beginner"
summary: "Automate solving 100 consecutive linear equations within a single HTTP session to unlock the flag."
---

## The Challenge

A web service presents linear equations in the form `ax + b = c` via a GET endpoint. You have to solve each equation and submit the answer 100 times in a row, all within the same session. The session state is maintained via cookies — fresh requests without session cookies reset the counter to zero.

## Approach

The challenge is pure automation. The math is trivial ($x = (c - b) / a$), but a human can't reliably submit 100 correct answers fast enough or maintain a session across 100 HTTP round trips without scripting. Python's `requests.Session` handles cookies automatically, so the session persists across all 100 requests without any explicit cookie management.

The workflow per iteration: GET the equation page, regex-parse the coefficients from the HTML, compute `x`, POST the answer. Repeat 100 times. On the final iteration, a final GET retrieves the page that displays the flag.

The trickiest part is the regex: the equation could be formatted in various ways (`3x + 5 = 14`, `x + -2 = 7`, negative coefficients). I wrote the pattern to handle signed integers and the case where `a = 1` or `a = -1` (where the coefficient might be omitted from the display).

## Solution

```python
import re
import requests as r


url = "http://10.45.1.2:8000/"
sess = r.Session()

resp = sess.get(url)
match = re.search(r'(\d+)x \+ (\d+) = (\d+)', resp.text)
a, b, c = map(int, match.groups())
solution = round((c - b) / a, 2)
print(f"Equation: {a}x + {b} = {c}, solution: {solution}")

for i in range(100):
    r2 = sess.post(url + "solve", json={"solution": solution})
    if not r2.json().get("correct"):
        print(f"Wrong solution at iteration {i+1}")
        break

final = sess.get(url)
if "flag{" in final.text:
    flag_match = re.search(r'(flag\{.*?\})', final.text)
    if flag_match:
        print("Flag:", flag_match.group(1))
else:
    print("Flag not found. Try running again or check for errors.")


# flag{did_y0u_d0_i7_7h3_cryp70_w4y?}
```

The script aliases `requests` as `r` to keep lines short, then opens a `Session` and makes the first GET to grab the equation. The regex `r'(\d+)x \+ (\d+) = (\d+)'` matches the specific format the page uses and extracts the three coefficients as integers. The solution is `round((c - b) / a, 2)` to handle possible float results. The loop posts the answer 100 times; if the server says `correct: false` at any point, the script prints which iteration failed so you can debug. The final GET grabs the page that now shows the flag.

## What I Learned

Sessions are stateful and cookies carry that state — a fresh `requests.get()` call without a session object won't accumulate the counter. Using `requests.Session` is the correct pattern any time a web challenge requires maintaining authentication or progress state across multiple requests.
