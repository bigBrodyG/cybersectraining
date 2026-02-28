#!/usr/bin/env python3
import ast
import math
import random
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

G = (
    0x43bf9535b2c484b67c68cb98bace14ae9526d955732e2e30ac0895ab6ba,
    0x4a9f13a6bd7bb39158cc785e05688d8138b05af9f1e13e01aaef7c0ab94,
)


def add_points(P, Q, p):
    return ((P[0] * Q[0] - P[1] * Q[1]) % p, (P[0] * Q[1] + P[1] * Q[0]) % p)


def multiply(P, n, p):
    Q = (1, 0)
    while n > 0:
        if n & 1:
            Q = add_points(Q, P, p)
        P = add_points(P, P, p)
        n >>= 1
    return Q


def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(out))


def is_probable_prime(n, k=10):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small_primes:
        if n % sp == 0:
            return n == sp
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = (pow(x, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factor(n):
    if n == 1:
        return []
    if is_probable_prime(n):
        return [n]
    d = pollard_rho(n)
    return factor(d) + factor(n // d)


def factor_with_multiplicity(n):
    factors = {}
    for f in factor(n):
        factors[f] = factors.get(f, 0) + 1
    return factors


def bsgs(g, h, order, p):
    if order == 1:
        return 0
    m = int(math.isqrt(order)) + 1
    table = {}
    e = (1, 0)
    for i in range(m):
        table[e] = i
        e = add_points(e, g, p)
    factor = multiply(g, order - m, p)
    gamma = h
    for j in range(m):
        if gamma in table:
            return j * m + table[gamma]
        gamma = add_points(gamma, factor, p)
    raise ValueError("dlog not found")


def crt(congruences):
    x = 0
    m = 1
    for r, mod in congruences:
        # Solve x ≡ r (mod mod)
        # with current x ≡ x (mod m)
        t = (r - x) % mod
        inv = pow(m, -1, mod)
        k = (t * inv) % mod
        x = x + k * m
        m *= mod
    return x, m


def discrete_log_pohlig_hellman(g, h, order, p):
    factors = factor_with_multiplicity(order)
    congruences = []
    for q, e in sorted(factors.items()):
        q_pow = q ** e
        g_i = multiply(g, order // q_pow, p)
        h_i = multiply(h, order // q_pow, p)
        x_i = bsgs(g_i, h_i, q_pow, p)
        congruences.append((x_i, q_pow))
    x, _ = crt(congruences)
    return x


def pkcs7_unpad(data: bytes, block_size=16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return data[:-pad_len]


def main():
    with open("/home/giordi/KingExchange/output.txt", "r", encoding="utf-8") as f:
        A = ast.literal_eval(f.readline().strip())
        B = ast.literal_eval(f.readline().strip())
        ct = bytes.fromhex(f.readline().strip())

    NA = A[0] * A[0] + A[1] * A[1] - 1
    NB = B[0] * B[0] + B[1] * B[1] - 1
    NG = G[0] * G[0] + G[1] * G[1] - 1
    p = math.gcd(NA, NB)
    p = math.gcd(p, NG)

    if not is_probable_prime(p):
        # Fall back to the largest prime factor if gcd has extra small factors.
        pf = factor(p)
        p = max(pf)

    order = p + 1
    # Ensure g has full order.
    factors = factor_with_multiplicity(order)
    g_order = order
    for q, e in factors.items():
        for _ in range(e):
            if g_order % q != 0:
                break
            if multiply(G, g_order // q, p) == (1, 0):
                g_order //= q
            else:
                break

    if g_order != order:
        raise ValueError("unexpected generator order")

    a = discrete_log_pohlig_hellman(G, A, order, p)
    shared = multiply(B, a, p)[0]
    key = sha256(long_to_bytes(shared)).digest()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    pt = pkcs7_unpad(pt)
    print(pt.decode())


if __name__ == "__main__":
    main()
