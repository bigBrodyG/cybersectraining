from pwn import *
import math
from collections import defaultdict

# Connect to the challenge
conn = remote('geometry-bash.challs.olicyber.it', 11005)

# Normalize vector direction
def normalize(vx, vy):
    if vx == 0 and vy == 0:
        return (0, 0)
    g = math.gcd(int(vx), int(vy))
    vx, vy = vx / g, vy / g
    if vx == 0:
        vy = 1
    elif vy == 0:
        vx = 1
    elif vy < 0 or (vy == 0 and vx < 0):
        vx, vy = -vx, -vy
    return (vx, vy)

# Check if projection list is symmetric
def is_symmetric(proj):
    proj.sort()
    n = len(proj)
    for i in range(n // 2):
        if not math.isclose(proj[i] + proj[-(i + 1)], proj[0] + proj[-1], abs_tol=1e-6):
            return False
    return True

# Solve for a single test case
def solve(points):
    n = len(points)
    dirs = set()
    
    for i in range(n):
        for j in range(i+1, n):
            # Vector from i to j, midpoint is symmetry axis
            mx = points[i][0] + points[j][0]
            my = points[i][1] + points[j][1]
            vx, vy = my, -mx  # perpendicular to midpoint vector

            if vx == 0 and vy == 0:
                continue
            vx, vy = normalize(vx, vy)

            projections = [p[0]*vx + p[1]*vy for p in points]
            if is_symmetric(projections):
                dirs.add((vx, vy))

    return -1 if len(dirs) > 1e6 else len(dirs)  # handle potential infinite case

# Start solving after prompt
conn.recvuntil(b'Press any key to begin!')
conn.sendline()
points = []

while True:
    line = conn.recvline().decode().strip()
    print(line)
    if line.startswith("Your answer"):
        break
    if line == "":
        continue
    try:
        x, y = map(int, line.split())
        points.append((x, y))
    except:
        continue

answer = solve(points)
print(answer)
print(f"Submitting: {answer}")
conn.sendline(str(answer).encode())

# Read final output (hopefully the flag)
conn.interactive()
