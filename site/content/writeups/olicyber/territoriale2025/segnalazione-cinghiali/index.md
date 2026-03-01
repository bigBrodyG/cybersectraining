---
title: "Segnalazione Cinghiali — Union-Based SQLi in Node/Express"
date: 2025-03-01
categories: ["Olicyber"]
series: ["Territoriale 2025"]
tags: ["web", "sqli", "union-injection", "sqlite", "nodejs"]
difficulty: "intermediate"
summary: "Union-based SQL injection in the report ID parameter of a Node.js/TypeScript Express app to leak the flag from a hidden table."
---

## The Challenge

"Segnalazione Cinghiali Cittadini" — Citizens' Wild Boar Reporting — is a Node.js/TypeScript Express web application backed by SQLite. The app lets users submit boar sightings and view them at `/report/:id`. Source and a Docker environment are provided.

Looking at `init.sql`, the database has at least two tables: one for reports and one for the flag. The flag table isn't exposed through any normal UI flow, but the `/report/:id` route directly interpolates the `:id` parameter into a SQL query with no sanitization.

## Approach

The first thing I did after spinning up the Docker environment was read the route handler. The query looked roughly like:

```sql
SELECT * FROM reports WHERE id = <id>
```

No prepared statement, just string interpolation. SQLite supports `UNION SELECT`, and I can query `sqlite_master` to enumerate tables and columns — which confirms the flag table's name and schema.

Since this is a SQLite app, `sqlite_master` is the information schema equivalent:

```sql
SELECT name, sql FROM sqlite_master WHERE type='table'
```

Once I had the table name (`flag`) and column name (`flag`), it was a one-shot union injection to extract the value.

The tricky part in practice is counting columns: the `reports` table query returns a fixed number of columns, and the UNION query must match that count. I used `NULL` padding to probe the column count first, incrementally adding NULLs until the union didn't error. Once the count was right, I swapped one NULL for `flag` from the `flag` table.

## Solution

All done manually through the browser or curl. The injection payloads:

**Probe column count (adjust until no error):**
```
/report/1 UNION SELECT NULL,NULL,NULL--
```

**Enumerate tables:**
```
/report/0 UNION SELECT name,sql,NULL FROM sqlite_master WHERE type='table'--
```

This reveals the flag table and its schema.

**Extract the flag:**
```
/report/0 UNION SELECT flag,NULL,NULL FROM flag LIMIT 1--
```

The flag appears in the first field of the returned report. The `id=0` trick ensures no real report rows match (so the response contains only the injected row), making the output unambiguous.

The Node.js Express app delivers the result as JSON or HTML depending on the Accept header — either way the flag value shows up in the response body.

## What I Learned

Source-code access makes SQL injection trivial to exploit: you read the query, count the columns, and write the payload. The interesting part was the reminder that modern web frameworks don't prevent SQL injection by default — the developer has to explicitly use parameterized queries. ORM doesn't save you if you drop to raw SQL.
