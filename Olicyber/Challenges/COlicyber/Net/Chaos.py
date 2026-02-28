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
