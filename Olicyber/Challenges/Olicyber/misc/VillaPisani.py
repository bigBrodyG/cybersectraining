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

    return False

if __name__ == "__main__":
    start = "00000000-0000-4000-0000-000000000000.maze.localhost"
    if not dfs(start):
        print("Flag not found.")
