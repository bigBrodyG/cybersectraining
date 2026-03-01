---
title: "Quantum Transport Layer — TLS ALPN Flag via gnutls-cli"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "tls", "alpn", "bash"]
difficulty: "beginner"
summary: "The TLS server returns the flag as the negotiated ALPN protocol name. Inject the server's hostname into /etc/hosts, connect with gnutls-cli specifying --alpn=flag, and read the flag from the TLS handshake output."
---

## The Challenge

A TLS server at port 10503 uses the ALPN extension (Application-Layer Protocol Negotiation) to expose the flag. ALPN lets a client propose a list of protocol names during the TLS handshake; the server responds with the one it supports. Here the "protocol" the server supports is the flag string itself.

## Approach

The hostname `fl4gg.quantum-transport-layer.test` doesn't resolve publicly — it points to a challenge IP. Add it to `/etc/hosts` temporarily, then connect with `gnutls-cli` using `--alpn=flag` to request the ALPN name `"flag"` in the ClientHello. The server echoes back its chosen ALPN value: the flag.

`--insecure` skips certificate validation. The script cleans `/etc/hosts` after running.

## Solution

```bash
#!/bin/sh 

IP_ADDRESS="5.75.221.48"
HOSTNAME="fl4gg.quantum-transport-layer.test"

if ! grep -q "$HOSTNAME" /etc/hosts; then
    # Add the entry to /etc/hosts
    echo "$IP_ADDRESS $HOSTNAME" | sudo tee -a /etc/hosts > /dev/null
    echo "Added $HOSTNAME to /etc/hosts."
fi

echo "$(gnutls-cli fl4gg.quantum-transport-layer.test:10503 --insecure --alpn=flag)"

if grep -q "$HOSTNAME" /etc/hosts; then
  # Remove the line containing the hostname
  sudo sed -i "/$HOSTNAME/d" /etc/hosts
  echo "Removed $HOSTNAME from /etc/hosts."
fi
```

The `grep -q` guard prevents duplicate `/etc/hosts` entries on re-runs. The `gnutls-cli` invocation connects over TLS, proposes `flag` as the ALPN string, and prints the full handshake including the server's chosen protocol — where the flag is.

## What I Learned

ALPN was designed so HTTP/2 and HTTP/1.1 can share port 443: the client proposes `h2` and `http/1.1` and the server picks one. Nothing stops a server from using any arbitrary string as a "protocol name", making it a convenient channel for hiding short secrets in the TLS handshake metadata rather than the application payload.
