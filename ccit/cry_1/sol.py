def solve_flag(ciphertext_hex):
    ct = bytes.fromhex(ciphertext_hex)
    flag = bytearray([0] * 40)
    
    # Initial values based on the flag format CCIT2024{...}
    flag[0] = ord('C')
    flag[1] = ord('C')
    flag[2] = ord('I')
    flag[3] = ord('T')
    flag[4] = ord('2')
    flag[5] = ord('0')
    flag[6] = ord('2')
    flag[7] = ord('4')
    flag[8] = ord('{')
    flag[39] = ord('}')
    
    # Function to solve one equation at a time
    def solve_equation(eq_idx, target_idx, *source_indices):
        xor_result = ct[eq_idx]
        for idx in source_indices:
            if flag[idx] == 0:  # If we don't know this value yet, we can't solve
                return False
            xor_result ^= flag[idx]
        flag[target_idx] = xor_result
        return True
    
    # Now we solve systematically
    progress = True
    iterations = 0
    
    while progress and iterations < 40:
        iterations += 1
        progress = False
        
        # Check for consistency with what we know
        if (flag[0] ^ flag[7] ^ flag[0] ^ flag[4]) & 0xFF != ct[0]:
            print("Warning: Inconsistency detected with equation 0")
        
        # Let's solve each equation where we know all but one variable
        
        # ct[9] = flag[4] ^ flag[39] ^ flag[7] ^ flag[9]
        if solve_equation(9, 9, 4, 39, 7): progress = True
        
        # ct[10] = flag[1] ^ flag[5] ^ flag[6] ^ flag[10]
        if solve_equation(10, 10, 1, 5, 6): progress = True
        
        # ct[11] = flag[11] ^ flag[5] ^ flag[2] ^ flag[4] ^ flag[7]
        if solve_equation(11, 11, 5, 2, 4, 7): progress = True
        
        # ct[12] = flag[6] ^ flag[12] ^ flag[5]
        if solve_equation(12, 12, 6, 5): progress = True
        
        # ct[13] = flag[13] ^ flag[1] ^ flag[5] ^ flag[1] ^ flag[39]
        # = flag[13] ^ flag[5] ^ flag[39] (flag[1] cancels out)
        if solve_equation(13, 13, 5, 39): progress = True
        
        # ct[14] = flag[7] ^ flag[14] ^ flag[8]
        if solve_equation(14, 14, 7, 8): progress = True
        
        # ct[15] = flag[15] ^ flag[39] ^ flag[6] ^ flag[2] ^ flag[7]
        if solve_equation(15, 15, 39, 6, 2, 7): progress = True
        
        # ct[16] = flag[16] ^ flag[39] ^ flag[2]
        if solve_equation(16, 16, 39, 2): progress = True
        
        # ct[17] = flag[17] ^ flag[8] ^ flag[39] ^ flag[7]
        if solve_equation(17, 17, 8, 39, 7): progress = True
        
        # ct[18] = flag[4] ^ flag[0] ^ flag[2] ^ flag[18]
        if solve_equation(18, 18, 4, 0, 2): progress = True
        
        # ct[19] = flag[2] ^ flag[19] ^ flag[0]
        if solve_equation(19, 19, 2, 0): progress = True
        
        # ct[20] = flag[5] ^ flag[4] ^ flag[20] ^ flag[0]
        if solve_equation(20, 20, 5, 4, 0): progress = True
        
        # ct[21] = flag[21] ^ flag[2] ^ flag[6]
        if solve_equation(21, 21, 2, 6): progress = True
        
        # ct[22] = flag[39] ^ flag[22] ^ flag[6] ^ flag[3] ^ flag[2]
        if solve_equation(22, 22, 39, 6, 3, 2): progress = True
        
        # ct[23] = flag[4] ^ flag[4] ^ flag[23] = flag[23]
        flag[23] = ct[23]
        
        # ct[24] = flag[3] ^ flag[0] ^ flag[5] ^ flag[24] ^ flag[1]
        if solve_equation(24, 24, 3, 0, 5, 1): progress = True
        
        # ct[25] = flag[0] ^ flag[25] ^ flag[2]
        if solve_equation(25, 25, 0, 2): progress = True
        
        # ct[26] = flag[8] ^ flag[26] ^ flag[5] ^ flag[0] ^ flag[39]
        if solve_equation(26, 26, 8, 5, 0, 39): progress = True
        
        # ct[27] = flag[39] ^ flag[27] ^ flag[1]
        if solve_equation(27, 27, 39, 1): progress = True
        
        # ct[28] = flag[1] ^ flag[1] ^ flag[28] ^ flag[2] ^ flag[2] = flag[28]
        flag[28] = ct[28]
        
        # ct[29] = flag[39] ^ flag[6] ^ flag[29] ^ flag[1]
        if solve_equation(29, 29, 39, 6, 1): progress = True
        
        # ct[30] = flag[6] ^ flag[0] ^ flag[6] ^ flag[30] ^ flag[3] = flag[0] ^ flag[30] ^ flag[3]
        if solve_equation(30, 30, 0, 3): progress = True
        
        # ct[31] = flag[1] ^ flag[8] ^ flag[31]
        if solve_equation(31, 31, 1, 8): progress = True
        
        # ct[32] = flag[3] ^ flag[0] ^ flag[0] ^ flag[32] = flag[3] ^ flag[32]
        if solve_equation(32, 32, 3): progress = True
        
        # ct[33] = flag[1] ^ flag[2] ^ flag[33]
        if solve_equation(33, 33, 1, 2): progress = True
        
        # ct[34] = flag[6] ^ flag[0] ^ flag[7] ^ flag[34] ^ flag[7]
        # = flag[6] ^ flag[0] ^ flag[34]
        if solve_equation(34, 34, 6, 0): progress = True
        
        # ct[35] = flag[6] ^ flag[39] ^ flag[4] ^ flag[2] ^ flag[35]
        if solve_equation(35, 35, 6, 39, 4, 2): progress = True
        
        # ct[36] = flag[36] ^ flag[5] ^ flag[6]
        if solve_equation(36, 36, 5, 6): progress = True
        
        # ct[37] = flag[2] ^ flag[7] ^ flag[8] ^ flag[37]
        if solve_equation(37, 37, 2, 7, 8): progress = True
        
        # ct[38] = flag[4] ^ flag[6] ^ flag[38] ^ flag[1]
        if solve_equation(38, 38, 4, 6, 1): progress = True
        
        # ct[39] = flag[39] ^ flag[39] ^ flag[6] ^ flag[3] = flag[6] ^ flag[3]
        if (flag[6] ^ flag[3]) & 0xFF != ct[39]:
            print("Warning: Inconsistency detected with equation 39")
    
    # Convert to bytes and return
    return bytes(flag)

# Decrypt the ciphertext
ciphertext_hex = '0654270a0c60490000107206371222064d6d00391e096171113b070d6453235e6339036b366a2f66'
flag = solve_flag(ciphertext_hex)

print(f"Flag: {flag.decode('ascii', errors='replace')}")

# Let's verify the solution by re-encrypting it
def generate_ciphertext(pt):
    ct = b''
    ct += (pt[0] ^ pt[7] ^ pt[0] ^ pt[4]).to_bytes(1, 'little')
    ct += (pt[4] ^ pt[4] ^ pt[3]).to_bytes(1, 'little')
    ct += (pt[3] ^ pt[1] ^ pt[5]).to_bytes(1, 'little')
    ct += (pt[1] ^ pt[2]).to_bytes(1, 'little')
    ct += (pt[6] ^ pt[39] ^ pt[0]).to_bytes(1, 'little')
    ct += (pt[7] ^ pt[3]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[7]).to_bytes(1, 'little')
    ct += (pt[0] ^ pt[1]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[39]).to_bytes(1, 'little')
    ct += (pt[4] ^ pt[39] ^ pt[7] ^ pt[9]).to_bytes(1, 'little')
    ct += (pt[1] ^ pt[5] ^ pt[6] ^ pt[10]).to_bytes(1, 'little')
    ct += (pt[11] ^ pt[5] ^ pt[2] ^ pt[4] ^ pt[7]).to_bytes(1, 'little')
    ct += (pt[6] ^ pt[12] ^ pt[5]).to_bytes(1, 'little')
    ct += (pt[13] ^ pt[1] ^ pt[5] ^ pt[1] ^ pt[39]).to_bytes(1, 'little')
    ct += (pt[7] ^ pt[14] ^ pt[8]).to_bytes(1, 'little')
    ct += (pt[15] ^ pt[39] ^ pt[6] ^ pt[2] ^ pt[7]).to_bytes(1, 'little')
    ct += (pt[16] ^ pt[39] ^ pt[2]).to_bytes(1, 'little')
    ct += (pt[17] ^ pt[8] ^ pt[39] ^ pt[7]).to_bytes(1, 'little')
    ct += (pt[4] ^ pt[0] ^ pt[2] ^ pt[18]).to_bytes(1, 'little')
    ct += (pt[2] ^ pt[19] ^ pt[0]).to_bytes(1, 'little')
    ct += (pt[5] ^ pt[4] ^ pt[20] ^ pt[0]).to_bytes(1, 'little')
    ct += (pt[21] ^ pt[2] ^ pt[6]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[22] ^ pt[6] ^ pt[3] ^ pt[2]).to_bytes(1, 'little')
    ct += (pt[4] ^ pt[4] ^ pt[23]).to_bytes(1, 'little')
    ct += (pt[3] ^ pt[0] ^ pt[5] ^ pt[24] ^ pt[1]).to_bytes(1, 'little')
    ct += (pt[0] ^ pt[25] ^ pt[2]).to_bytes(1, 'little')
    ct += (pt[8] ^ pt[26] ^ pt[5] ^ pt[0] ^ pt[39]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[27] ^ pt[1]).to_bytes(1, 'little')
    ct += (pt[1] ^ pt[1] ^ pt[28] ^ pt[2] ^ pt[2]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[6] ^ pt[29] ^ pt[1]).to_bytes(1, 'little')
    ct += (pt[6] ^ pt[0] ^ pt[6] ^ pt[30] ^ pt[3]).to_bytes(1, 'little')
    ct += (pt[1] ^ pt[8] ^ pt[31]).to_bytes(1, 'little')
    ct += (pt[3] ^ pt[0] ^ pt[0] ^ pt[32]).to_bytes(1, 'little')
    ct += (pt[1] ^ pt[2] ^ pt[33]).to_bytes(1, 'little')
    ct += (pt[6] ^ pt[0] ^ pt[7] ^ pt[34] ^ pt[7]).to_bytes(1, 'little')
    ct += (pt[6] ^ pt[39] ^ pt[4] ^ pt[2] ^ pt[35]).to_bytes(1, 'little')
    ct += (pt[36] ^ pt[5] ^ pt[6]).to_bytes(1, 'little')
    ct += (pt[2] ^ pt[7] ^ pt[8] ^ pt[37]).to_bytes(1, 'little')
    ct += (pt[4] ^ pt[6] ^ pt[38] ^ pt[1]).to_bytes(1, 'little')
    ct += (pt[39] ^ pt[39] ^ pt[6] ^ pt[3]).to_bytes(1, 'little')
    return ct

# Verify our solution
generated_ct = generate_ciphertext(flag)
if generated_ct.hex() == ciphertext_hex:
    print("Verification successful! Our solution is correct.")
else:
    print("Verification failed. Our solution might be incorrect.")
    print(f"Original CT: {ciphertext_hex}")
    print(f"Generated CT: {generated_ct.hex()}")