---
title: "Useless — Flag Hidden in PCAPNG via strings"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["net", "forensics", "pcap"]
difficulty: "beginner"
summary: "Run strings on the PCAPNG and grep for 'flag' — the flag is stored as plain ASCII inside the capture file and visible without any packet parsing."
---

## The Challenge

A PCAPNG file is given. The capture is described as "useless" — almost nothing interesting is happening at the network level. The flag is planted as a raw string in the file content rather than hidden inside a protocol's payload.

## Approach

`strings` extracts all printable ASCII sequences from a binary file. `grep 'flag'` filters the output to lines containing the flag pattern. No packet dissection, no protocol parsing — the flag is in cleartext in the binary.

## Solution

```python
import os
print(os.system("strings capture.pcapng | grep 'flag'")) # straight like that lol
```

`os.system` runs the shell pipeline and that's all there is to it. The inline comment "straight like that lol" captures the author's reaction to how trivially the flag was found.

## What I Learned

`strings | grep flag` is always the first tool to run on any unknown binary or capture file. PCAPNG has a rich metadata format with comment fields, custom blocks, and interface descriptions — any of these can carry arbitrary text that `strings` will surface immediately, before spending time with Wireshark.
