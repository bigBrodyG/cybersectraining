---
title: "Dynamic Secret"
date: 2026-02-28
categories: ["Olicyber"]
series: ["Territoriale 2026 Demo"]
tags: ["misc", "strace", "linux", "dynamic-analysis"]
difficulty: "beginner"
summary: "Use strace to trace the runtime syscalls of a binary and read the secret it loads from a file."
---

## The Challenge

`dynamicsecret` is a binary that loads something at runtime — from a file on disk or from an environment variable. Running it normally either crashes, prints nothing useful, or asks for credentials it won't verify without the secret in place. The flag is that secret.

## Approach

When a binary loads data from a file or environment at runtime, it has to make syscalls to do so. On Linux that means `openat`, `read`, `getenv`, and friends — all of which `strace` intercepts and prints verbatim. I don't need to reverse the binary statically; I just run it under `strace` and watch what happens.

`strace` traces every syscall and prints the arguments and return values. When the binary calls `openat` to open a secret file, you see the path. When it calls `read`, you see the data. If it uses `getenv`, you see the variable name. Whatever mechanism it uses, `strace` will show it.

There's no exploitation here — it's a reconnaissance technique. The binary is doing exactly what it's supposed to do; I'm just watching.

## Solution

```bash
strace ./dynamicsecret 2>&1 | head -60
```

The `2>&1` redirect is important because `strace` writes to stderr by default. Piping through `head` keeps the output manageable — you usually see the interesting syscalls in the first few dozen lines, before the binary gets to its main logic.

In the output, the relevant line looks something like:

```
openat(AT_FDCWD, "/path/to/secret_file", O_RDONLY) = 3
read(3, "flag{trust_the_runtime_path_e05f6877}\0", 64) = 37
```

The `read` call's second argument is the buffer contents — strace pretty-prints strings for you. The flag is right there: `flag{trust_the_runtime_path_e05f6877}`.

If the binary loaded from an environment variable instead, you'd see:

```
getenv("SECRET_VAR")                    = "flag{...}"
```

Either way, `strace` catches it. No disassembly, no decompiler, no guessing.

## What I Learned

`strace` is one of the most underused tools in a CTF toolkit. Any time a binary "loads a secret at runtime," it exposes that secret through syscalls — and syscalls are always visible to a tracer. Before opening Ghidra, try `strace`.
