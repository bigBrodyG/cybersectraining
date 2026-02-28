# Walkthrough: Solving "hidden_variable"

## Overview
The goal of this challenge was to retrieve a flag from the [hidden_variable](file:///home/giordi/Repos/cybersectraining/Camp2026/Binary/hidden_variable/hidden_variable) binary. As the name suggested, the flag was embedded directly inside the binary as an unused variable.

## Static Analysis
Upon examining the symbols in the binary using `nm`, we found an interesting symbol named `fl4g` in the Data section (`.data`).

```bash
nm hidden_variable | grep fl4g
0000000000004020 D fl4g
```

We extracted the first few bytes from the `.data` section at the symbol `fl4g`. We noticed that the string was stored as an array of integers (4 bytes per character):
`b'f\x00\x00\x00l\x00\x00\x00a\x00\x00\x00g\x00\x00\x00{\x00...'`

## Exploit Development
To automate reading this format, we wrote a simple pwntools script to:
1. Load the ELF binary.
2. Read 256 bytes starting from the `fl4g` symbol address.
3. Slice the data, taking every 4th byte, and splitting by null byte to retrieve the valid ASCII characters.

Here is the extraction script ([solve.py](file:///home/giordi/Repos/cybersectraining/Camp2026/Binary/hidden_variable/solve.py)):

```python
from pwn import *

elf = ELF("./hidden_variable")
flag_data = elf.read(elf.symbols["fl4g"], 256)
flag = flag_data[::4].split(b"\x00")[0].decode("utf-8")
print(f"Flag is: {flag}")
```

## Solution
Running the extraction script yielded the complete flag cleanly:

**Flag**: `flag{unu53d_v4r5_4r3_5711_c0mp1l3d}`
