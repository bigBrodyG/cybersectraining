from pwn import *
from math import gcd, isqrt

def solve(N):
    for g in range(1, isqrt(N) + 1):
        if N % g != 0:
            continue
        for d in [g, N // g]:
            target = (N // d) - 1
            if target <= 0:
                continue
            for m in range(1, isqrt(target) + 1):
                if target % m != 0:
                    continue
                n = target // m
                if gcd(m, n) == 1:
                    a, b = d * max(m, n), d * min(m, n)
                    if a > b:
                        return a, b
    return None, None


# Connect to remote challenge
conn = remote("nt-master.challs.olicyber.it", 11001)

# Read initial messages
print(conn.recvline().decode())
print(conn.recvline().decode())
print(conn.recvline().decode())

# Loop through the 10 tests
for _ in range(10):
    conn.recvline()
    line = conn.recvline().decode()
    print(line.strip())

    # Parse the number N
    N = int(line.strip().split('=')[1])
    
    a, b = solve(N)
    
    if a is None:
        print(f"Could not solve for N={N}")
        break

    response = f"{a} {b}"
    print(f"Sending: {response}")
    conn.sendline(response)

# Final response: possibly the flag
while True:
    try:
        print(conn.recvline().decode().strip())
    except EOFError:
        break
