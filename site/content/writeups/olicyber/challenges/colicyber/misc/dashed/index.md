---
title: "Dashed — Six-Layer Encoding Chain: Morse → Hex → Binary → Base64 → Caesar"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["misc", "encoding", "morse", "python"]
difficulty: "intermediate"
summary: "Decode a Morse code file, strip hex prefixes, convert to binary, interpret as Base64, then apply a Caesar shift derived from the first character — five transforms chained together."
---

## The Challenge

A `dashed.txt` file full of Morse code symbols. The flag is buried under five successive encoding layers. The comment in the script says it best: "BASTA FARLO CON CYBERCHEF MA NON AVEVO NULLA DA FARE" (you could just use CyberChef, but I had nothing better to do) — that is the honest summary of this challenge.

## Approach

Working backwards through the layers:

1. **Morse decode**: split the file on spaces, reverse-lookup each symbol in a dictionary to get a character.
2. **Strip hex noise**: the Morse decodes to something like `0X4A,0X15,...`. Strip `0X` and commas, split on spaces.
3. **Hex to bytes**: each remaining segment is a two-character hex value; decode it.
4. **Binary string**: concatenate the resulting bytes to get a binary string (`0` and `1` characters).
5. **Binary to text**: convert the binary string to an integer, then to bytes → gives a Base64 string.
6. **Base64 decode**: yields a Caesar-shifted string.
7. **Caesar decode**: the shift is `ord(first_char) - ord('f')` — the first letter should be `f` (start of `flag{`), so the shift is derived directly from the ciphertext.

## Solution

```python

## BASTA FARLO CON CYBERCHEF MA NON AVEVO NULLA DA FARE 😵

from base64 import b64decode
dizionario_morse = {'A':'.-', 'B':'-...', # template trovabile ovunque
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

flag = str(open("dashed.txt", "r").read()).split(" ")
temp_string = ""
for words in flag:
    for i in dizionario_morse:
        if dizionario_morse[i] == words:
            temp_string += i
temp_string = temp_string.replace("0X", "").replace(",", "").split(" ")
flag2 = ""
for numbers in temp_string:
    flag2 += bytes.fromhex(numbers).decode("ascii")
flag3 = int(flag2, 2).to_bytes(((flag2.__len__()) + 7) // 8, 'big').decode("ascii")
flag4 = b64decode(flag3).decode().replace("\n", "")
shift = -1
for i in flag4:
    if shift == -1:
        shift = ord(i) - ord('f')
    if i in "abcdefghijklmnopqrstuvwxyz" or i in str("abcdefghijklmnopqrstuvwxyz").upper():
        if i in "abcdefghijklmnopqrstuvwxyz":
            pos = ord(i) - ord('a')
            new_pos = (pos + shift) % 26
            print(chr(new_pos + ord('a')), end="")
        else:
            pos = ord(i) - ord('A')
            new_pos = (pos + shift) % 26
            print(chr(new_pos + ord('A')), end="")
    else:
        print(i, end="")
```

The Morse decode builds `temp_string` by reverse-looking up each symbol. After stripping `0X` and commas, each remaining token is two hex digits — concatenating their ASCII decodes gives a string of `0` and `1` characters. `int(flag2, 2).to_bytes(...)` is the binary-to-bytes step. `b64decode` unwraps the Base64 layer. The Caesar shift is derived by comparing the first character against `'f'` — valid since every flag starts with `flag{`.

## What I Learned

Heavily layered encoding challenges reward systematic peeling: work from the outermost layer inward, verify each step produces human-readable output, and never assume you know the layer count until output looks like a flag. The Caesar key derivation trick (compute shift from known first character) is broadly applicable to any encoding where you know one plaintext output char.
