#!/usr/bin/env python3
from pwn import *
import os

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

def solve():
    binary_path = '/home/giordi/Repos/cybersectraining/Territoriale/Binary/revme'
    exe = ELF(binary_path)
    target_addr = exe.symbols['target']
    target_data = list(exe.read(target_addr, 36))
    
    buf = target_data[:]
    buf.reverse()
    
    for i in range(36):
        buf[i] = (buf[i] - i) & 0xff
        shift = i % 8
        buf[i] = ((buf[i] >> shift) | (buf[i] << (8 - shift))) & 0xff
        buf[i] ^= 0x37
        
    flag_str = bytes(buf).decode('utf-8', errors='ignore')
    print(f"Flag found: {flag_str}")

if __name__ == "__main__":
    solve()

# flag{reverse_me_if_you_can_5c0e9b38}