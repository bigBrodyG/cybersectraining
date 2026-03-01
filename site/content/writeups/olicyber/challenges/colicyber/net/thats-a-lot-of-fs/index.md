---
title: "That's a Lot of Fs — Flag in Ethernet Destination MAC via Custom EtherType"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "forensics", "pcap", "scapy", "python"]
difficulty: "intermediate"
summary: "Filter Ethernet frames with EtherType 0xffff — the custom protocol used by this challenge — collect the destination MAC address from each matching frame, interpret the first two hex bytes as ASCII, and concatenate to reveal the flag."
---

## The Challenge

A PCAP full of Ethernet frames. Most have standard EtherTypes (IPv4, ARP, etc.). A subset uses EtherType `0xffff` — an undefined/custom value. These frames carry the flag one character at a time encoded in the destination MAC address.

## Approach

Scapy's `rdpcap` loads all frames. For each frame, check `eth_layer.type == 0xffff`. The destination MAC in these frames is of the form `XX:YY:ZZ:...` where the first two hex digits (`mac[0:2]`) encode one ASCII character of the flag. Collecting them in order and decoding with `chr(int(mac[0:2], 16))` gives the full flag string.

## Solution

```python
from scapy.all import rdpcap, Ether
packets = rdpcap("net2.pcap")

dest_mac_addresses = []
for packet in packets:
    if Ether in packet:
        eth_layer = packet[Ether]

        if eth_layer.type == 0xffff:
            dest_mac_addresses.append(eth_layer.dst)

flag = ''
for mac in dest_mac_addresses:
    flag += chr(int(mac[0:2], 16))
print(flag)
```

`rdpcap` loads the capture into a list of Scapy packets. The `if Ether in packet` guard avoids crashes on non-Ethernet frames. `eth_layer.type == 0xffff` identifies the custom protocol frames. `mac[0:2]` extracts the first byte of the destination MAC as two hex characters. `chr(int(..., 16))` converts it to ASCII. The characters in capture order spell out the flag.

## What I Learned

Covert channels can use any packet field that an attacker controls. Destination MAC addresses in raw Ethernet frames are freely settable — no protocol enforcement stops you from encoding arbitrary data one byte at a time. Custom EtherTypes (`0xffff` to `0xffff` is the unofficial range) are the common choice for in-band signalling outside normal protocol stacks.
