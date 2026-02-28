#!/usr/bin/env python3
import socket
import struct
import random

ROUND_CONST = [
    3243810922, 2109166420, 1261644, 284795533,
    267721891, 1428520712, 451254836, 3023120923,
    3616733408, 3544909379, 1141941182, 3419528971,
    3988935951, 3469132367, 639675417, 2336458540,
]

IV = [
    747420564, 1330225282, 106386925, 1126501333,
    1458865636, 4100469049, 1339981680, 3086093422,
    1797395789, 1644118404, 248157630, 4272628878,
    1220271058, 3463197254, 2820463463, 186181749,
]

MASK32 = 0xFFFFFFFF


def lrot(x, y):
    return ((x << y) | (x >> (32 - y))) & MASK32


def perm(data):
    v = data[:]
    for i in range(1024):
        v[0] ^= ROUND_CONST[i & 0xF]
        for j in range(16):
            t = v[j]
            t = (t + v[j - 4]) & MASK32
            t = t ^ lrot(t, 21) ^ lrot(t, 3)
            t = t ^ v[j - 2]
            t = (t + v[(j + 2) & 0xF]) & MASK32
            t = t ^ lrot(t, 16)
            t = t ^ v[(j + 1) & 0xF]
            t = t ^ ROUND_CONST[j]
            v[j] = t
    return v


def custom_hash(user_input: bytes) -> str:
    data = [int.from_bytes(user_input[i:i + 4], "little") for i in range(0, len(user_input), 4)]
    s = IV[:]
    datalen = len(data)
    while datalen >= 16:
        s = [s[i] ^ data[i] for i in range(16)]
        s = perm(s)
        datalen -= 16
        data = data[16:]
    for i in range(datalen):
        s[i] ^= data[i]
    s[datalen] ^= 1
    s = perm(s)
    h = b"".join([x.to_bytes(4, "little") for x in s]).hex()
    return h


# Computes the updated v[0] after step j=0 in round i=0.
def step0_output(x0, v):
    # v is the 16-word input state before the round-constant XOR.
    v0 = x0 ^ ROUND_CONST[0]
    t = v0
    t = (t + v[12]) & MASK32
    t = t ^ lrot(t, 21) ^ lrot(t, 3)
    t = t ^ v[14]
    t = (t + v[2]) & MASK32
    t = t ^ lrot(t, 16)
    t = t ^ v[1]
    t = t ^ ROUND_CONST[0]
    return t


def find_collision_x0(v):
    x0 = v[0]
    target = step0_output(x0, v)
    # Deterministic search over a window; expected to hit within ~2^16 tries.
    for k in range(1, 1 << 17):
        x0p = (x0 + k) & MASK32
        if step0_output(x0p, v) == target:
            return x0p
    # Fallback random search (should be very fast if reached).
    while True:
        x0p = random.getrandbits(32)
        if x0p != x0 and step0_output(x0p, v) == target:
            return x0p


def collide_message(msg: bytes) -> bytes:
    if len(msg) != 192:
        raise ValueError("Expected 192-byte message")
    block1 = msg[:64]
    block2 = msg[64:128]
    block3 = msg[128:192]

    block1_words = [int.from_bytes(block1[i:i + 4], "little") for i in range(0, 64, 4)]
    x = [IV[i] ^ block1_words[i] for i in range(16)]

    x0p = find_collision_x0(x)
    x[0] = x0p

    new_block1_words = [IV[i] ^ x[i] for i in range(16)]
    new_block1 = b"".join(w.to_bytes(4, "little") for w in new_block1_words)

    new_msg = new_block1 + block2 + block3
    if new_msg == msg:
        raise RuntimeError("Collision search failed: identical message")
    return new_msg


def solve_remote(host: str, port: int):
    with socket.create_connection((host, port)) as s:
        f = s.makefile("rwb", buffering=0)
        for _ in range(20):
            line = f.readline()
            if not line:
                raise RuntimeError("Connection closed")
            msg = line.strip().decode()
            raw = msg.encode()
            coll = collide_message(raw)
            f.write(coll.hex().encode() + b"\n")
            resp = f.readline()
            if not resp:
                raise RuntimeError("No response")
            # If the server rejects, it will close soon after.
        flag = f.readline().strip().decode()
        print(flag)


if __name__ == "__main__":
    # Quick local sanity test
    # Generate a random message and verify collision.
    rnd = bytes(random.choice(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(192))
    coll = collide_message(rnd)
    assert coll != rnd
    assert custom_hash(rnd) == custom_hash(coll)

    # Uncomment to solve remote challenge.
    solve_remote("primate-hash.challs.olicyber.it", 18004)
