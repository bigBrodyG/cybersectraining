---
title: "Based and Encoded — Multi-Format Encoding Bot"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "encoding", "automation", "pwntools"]
difficulty: "beginner"
summary: "A JSON-framed server demands conversions between base64, hex, and binary in both encode and decode directions. Write a bot that parses the Italian operation description and returns the correct transformed value."
---

## The Challenge

The server sends a JSON object with a `message` field and an Italian instruction describing the conversion: `da base64`, `da esadecimale`, `da binario`, `a base64`, `a esadecimale`, `a binario`. Respond with `{"answer": "..."}` and repeat until the flag appears.

## Approach

Six transformations, each handled by one branch:

- `da base64` → `b64decode(message)`
- `da esadecimale` → `bytes.fromhex(message)`
- `da binario` → convert binary string to int, then to bytes
- `a base64` → `b64encode(message.encode())`
- `a esadecimale` → `message.encode().hex()`
- `a binario` → format each character as 8-bit binary, strip leading zero if the string doesn't start with `1`

The only tricky case is `a binario`: standard binary representation of an ASCII string can have a leading zero byte, and the server apparently strips/ignores the leading `0` bit, so we check whether `binstr[0]` is `'1'` and if not walk forward to the first `'1'`.

The response body is always `b'{"answer": "' + value + b'"}`.

## Solution

```python
#!/usr/bin/env python3

from pwn import *
from base64 import b64decode, b64encode
import re

r = remote("based.challs.olicyber.it", 10600)
r.recvuntil(b'\n\n')

def bin_to_str(x):
    ''' Copiata lol '''
    my_int = int(x, base=2)
    my_str = my_int.to_bytes((my_int.bit_length() + 7)//8, 'big')
    return my_str

while True:
	t = r.recv(1000).decode()
	print(t)
	if 'da base64' in t:
		t = t.split('\n')
		j = eval(t[1])
		r.sendline(b'{"answer": "' +  b64decode(j["message"].encode()) + b'"}')
	elif 'da esadecimale' in t:
		t = t.split('\n')
		j = eval(t[1])
		r.sendline(b'{"answer": "' + bytes.fromhex(j["message"]) + b'"}')
	elif 'da binario' in t:
		t = t.split('\n')
		j = eval(t[1])
		r.sendline(b'{"answer": "' + bin_to_str("0b"+j["message"]) + b'"}')
	elif 'a base64' in t:
		t = t.split('\n')
		j = eval(t[1])
		r.sendline(b'{"answer": "' + b64encode(j["message"].encode()) + b'"}')
	elif 'a esadecimale' in t:
		t = t.split('\n')
		j = eval(t[1])
		r.sendline(b'{"answer": "' + j["message"].encode().hex().encode() + b'"}')
	elif 'a binario' in t:
		t = t.split('\n')
		j = eval(t[1])
		binstr = ''.join(format(ord(i), '08b') for i in j["message"])
		if binstr[0] != '1':
			for i in range(len(binstr)):
				if binstr[i] == '1':
					binstr = binstr[i:]
					break
		r.sendline(b'{"answer": "' +  binstr.encode() + b'"}')
	else:
		print("skill issue", t)
	flag = r.recvuntil(b'\n\n')
	if b'flag' in flag.lower():
		print(flag)
		break
```

`eval(t[1])` parses the raw JSON line as a Python dict — quick and dirty but fine for CTF. The response is assembled as raw bytes to avoid encoding issues where the decoded/encoded value might not be valid UTF-8.

## What I Learned

Encoding challenges are solved faster by just implementing all six directions up front rather than trying to predict which direction the server picks. The `bin_to_str` helper — `int(x, 2).to_bytes(...)` — is a pattern worth memorising: it converts an arbitrary-length binary string to bytes without looping character by character.
