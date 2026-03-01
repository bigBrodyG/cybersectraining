---
title: "Chaos — TCP Payload Reconstruction from PCAP"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "forensics", "pcap", "python"]
difficulty: "beginner"
summary: "Filter a PCAP for TCP packets, decode each packet's payload from hex, and concatenate them in order — the resulting byte stream contains the flag."
---

## The Challenge

A PCAP file is given. The capture looks messy (hence "Chaos") but all the relevant data lives in TCP payloads. The flag is reconstructed by reassembling the data chunks in capture order.

## Approach

`pyshark.FileCapture` with `display_filter='tcp'` filters out everything except TCP. Each packet exposes `i.tcp.payload` as a hex string — `bytes.fromhex()` decodes it. Packets without a payload field raise `AttributeError`, which the try/except silently discards. Concatenating all decoded payloads in order gives the full stream, which contains the flag.

The hardcoded `flag` assignment at the bottom is the solver's own note confirming the found flag — it doesn't affect execution.

## Solution

```python
#!/usr/bin/env python3
import pyshark

cap = pyshark.FileCapture('capture.pcap', display_filter='tcp')
flag = ''
for i in cap:
    try:
        flag += bytes.fromhex(i.tcp.payload).decode().strip()
    except AttributeError:
        pass
print(flag)
flag = "flag{T00_MUTCH_CH405}"
```

`display_filter='tcp'` is passed directly to tshark under the hood, so only TCP packets reach the loop. Each `i.tcp.payload` is a space-separated or raw hex string — `bytes.fromhex` handles both (after stripping spaces if needed). The final `print(flag)` emits the reassembled stream.

## What I Learned

pyshark exposes Wireshark's entire dissector tree through Python attributes. The most common pattern in PCAP challenges is: filter by protocol, iterate packets, extract the relevant field, concatenate. `AttributeError` on missing fields is the standard exception to catch — not every TCP packet has a payload layer.
