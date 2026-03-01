import subprocess
import re
import struct

def gf16_add(a, b):
    return a ^ b

def gf16_mul(a, b):
    p = 0
    for _ in range(4):
        if b & 1: p ^= a
        a <<= 1
        if a & 0x10: a ^= 0x13
        b >>= 1
    return p

gf16_inv = [0]*16
for i in range(1, 16):
    for j in range(1, 16):
        if gf16_mul(i, j) == 1:
            gf16_inv[i] = j

def gf16_div(a, b):
    if b == 0: raise ZeroDivisionError
    if a == 0: return 0
    return gf16_mul(a, gf16_inv[b])

def solve_linear_system(A, b):
    # Gaussian elimination over GF(16)
    n = len(A)
    m = len(A[0])
    
    # augmented matrix
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    
    row = 0
    for col in range(m):
        if row >= n: break
        
        # find pivot
        pivot_row = row
        while pivot_row < n and M[pivot_row][col] == 0:
            pivot_row += 1
            
        if pivot_row == n:
            continue # free variable or no solution
            
        M[row], M[pivot_row] = M[pivot_row], M[row]
        
        pivot_val = M[row][col]
        inv_pivot = gf16_inv[pivot_val]
        
        for j in range(col, m + 1):
            M[row][j] = gf16_mul(M[row][j], inv_pivot)
            
        for i in range(n):
            if i != row and M[i][col] != 0:
                factor = M[i][col]
                for j in range(col, m + 1):
                    M[i][j] ^= gf16_mul(factor, M[row][j])
                    
        row += 1
        
    solution = [0]*m
    for i in range(row):
        # find leading 1
        for j in range(m):
            if M[i][j] == 1:
                solution[j] = M[i][m]
                break
    return solution

def get_sig(j, val):
    proc = subprocess.Popen(["python3", "server.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, err = proc.communicate("1\n" + str(0x5e96 + j*0x18) + "\n0\n" + str(val) + "\n")
    match = re.search(r"sm:\s*([a-f0-9]+)", out)
    if match:
        return match.group(1)
    return None

def hex_to_nibbles(h):
    return [int(c, 16) for c in h]

O_matrix = []
k = 4
n = 64
o = 18
v = 46

print("Starting extraction of O...")
for j in range(v):
    print(f"Extracting row {j}...")
    A = []
    b = []
    
    queries = 0
    while len(A) < 26:
        sig_hex = get_sig(j, 13) # SIB patch 1e -> 1d
        if not sig_hex: continue
        
        nibbles = hex_to_nibbles(sig_hex)
        s_nibbles = nibbles[:256]
        
        for i in range(k):
            s_i = s_nibbles[i*n : (i+1)*n]
            s_val = s_i[j]
            x_i = s_i[46:64]
            
            eq = list(x_i)
            for c_idx in range(4):
                eq.append(1 if c_idx == i else 0)
                
            A.append(eq)
            b.append(s_val)
            
        queries += 1
        
    sol = solve_linear_system(A, b)
    O_row = sol[:18]
    O_matrix.append(O_row)
    print(f"Row {j}: {O_row}")

with open("O_matrix.txt", "w") as f:
    for row in O_matrix:
        f.write(",".join(map(str, row)) + "\n")
print("Extraction complete!")
