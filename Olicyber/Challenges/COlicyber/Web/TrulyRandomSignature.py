#!/usr/bin/env python3
import requests

def solve():
    site = "http://trulyrandomsignature.challs.olicyber.it"
    s = requests.Session()
    
    print("--- Request 1 (Session) ---")
    r1 = s.get(site)
    if 'Set-Cookie' in r1.headers:
        print("[-] Set-Cookie present")
    else:
        print("[+] No Set-Cookie")
        
    print(f"Cookies in jar: {s.cookies.get_dict()}")
        
    print("\n--- Request 2 (Session) ---")
    r2 = s.get(site)
    if 'Set-Cookie' in r2.headers:
        print("[-] Set-Cookie present")
    else:
        print("[+] No Set-Cookie")

if __name__ == "__main__":
    solve()