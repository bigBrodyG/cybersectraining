---
title: "Villa Pisani — DNS Maze DFS via CNAME Records"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "networking", "dns", "python"]
difficulty: "intermediate"
summary: "Navigate a DNS-based labyrinth by following CNAME records in four compass directions (up/down/left/right) and reading TXT records until one contains the flag. Depth-first search with a visited set prevents loops."
---

## The Challenge

The server runs a custom DNS resolver on port 10500. Each DNS node in the maze is a hostname. Querying `CNAME` for `direction.nodename` (where direction is `up`, `down`, `left`, or `right`) either fails (dead end) or returns the next node's hostname. `TXT` records on a node might contain the flag.

## Approach

Standard graph DFS with a visited set to avoid cycles. For each node:

1. Query `TXT` — if any result contains `"flag"`, print and return.
2. For each of the four directions, query `CNAME` with a `direction.nodename` pattern. If a CNAME exists, recurse into that node's hostname.

The `dns.resolver.Resolver` is pointed at the challenge server's IP and port. Exceptions (no answer, NXDOMAIN, timeout) are silently ignored — they just mean that direction is a dead end.

## Solution

```python
#!/usr/bin/env python3
import socket
import dns.resolver

# Configure the custom DNS server and port
res = dns.resolver.Resolver()
res.nameservers = [ socket.gethostbyname("pisani.challs.olicyber.it") ]
res.port = 10500
res.timeout = 5
res.lifetime = 5

visited = set()

def dfs(name):
    """Depth‑first search through the DNS maze."""
    if name in visited:
        return False
    visited.add(name)

    # 1) Try to get a TXT record for this node
    try:
        answers = res.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        answers = []

    for rdata in answers:
        # rdata.strings is a list of byte-strings; join and decode
        txt = b"".join(rdata.strings).decode('utf-8', errors='ignore')
        if "flag" in txt:
            print("FOUND:", txt)
            return True
        else:
            # If it's a navigation hint, it might start with e.g. "Navigate:"
            print(f"{name} TXT → {txt}")

    # 2) Otherwise, look up CNAMEs for the four possible directions
    for direction in ("up", "down", "left", "right"):
        target = f"{direction}.{name}"
        print(f"Trying {target}...")
        try:
            cname_ans = res.resolve(target, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue

        # Each CNAME RR has a .target attribute (a Name); str() yields the FQDN
        for rdata in cname_ans:
            next_name = str(rdata.target).rstrip('.')
            if dfs(next_name):
                return True
```

`res.nameservers` and `res.port` point the `dnspython` resolver at the challenge server rather than the system resolver. The `visited` set prevents infinite loops in cyclic mazes. `rdata.strings` is a list of byte chunks that need joining before decoding — a minor but crash-causing gotcha if skipped.

## What I Learned

DNS is a general-purpose data transport, not just a name-resolution protocol. Any record type can carry arbitrary data — TXT records hold strings, CNAME records can chain to arbitrary names. Building a DFS over CNAME-connected hostnames is straightforward once you see the graph structure the server is implementing.
