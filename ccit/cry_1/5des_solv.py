#!/usr/bin/env python3
from pwn import remote
from Crypto.Cipher import DES
import re
import binascii

# --- Helpers for 5DES key operations ---
# Given an 8-byte key and 40-byte plaintext,
# the new 5DES key is computed as:
#    new_key = DES(user_key).encrypt( DES(user_key).encrypt(user_plain) )
def new_5des_key(user_plain, user_key):
    cipher = DES.new(user_key, DES.MODE_ECB)
    tmp = cipher.encrypt(user_plain)
    new_key = cipher.encrypt(tmp)
    return new_key

# Build the 5DES ciphers – we split the 40-byte key into five 8-byte keys.
def create_des5(new_key):
    keys = [new_key[i*8:(i+1)*8] for i in range(5)]
    ciphers = [DES.new(k, DES.MODE_ECB) for k in keys]
    return ciphers

# Inverse of the 5DES encryption chain.
# During encryption, the chain is:
#   for i in 0..4:
#     if i is even: encrypt using cipher[i]
#     if i is odd:  decrypt using cipher[i]
# Decryption reverses the order and swaps the operations.
def des5_decrypt(ciphers, ciphertext):
    tmp = ciphertext
    for i in reversed(range(5)):
        if i % 2 == 1:
            tmp = ciphers[i].encrypt(tmp)
        else:
            tmp = ciphers[i].decrypt(tmp)
    return tmp

# --- Interaction with the remote service ---
def set_keys(p, user_plain, user_key):
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'1')
    x = p.recvuntil(b'Plaintext (hex): ')
    print(x)
    p.sendline(user_plain.hex().encode())
    x = p.recvuntil(b'Key (hex): ')
    print(x)
    p.sendline(user_key.hex().encode())
    x = p.recvuntil(b'Key set with success')
    print(x)

def encrypt_flag(p):
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'3')
    x = p.recvuntil(b'Flag encryption succeded')
    print(x)

# This leak function has been adjusted to try and capture any hexadecimal data returned
# when option 5 ("decrypt") is called.
def leak_encrypted_flag(p):
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'5')
    # wait to accumulate output; adjust timeout if needed
    data = p.recv(timeout=2)
    # Look for a hex string in the output using a regex.
    m = re.search(b'([0-9a-fA-F]{16,})', data)
    if m:
        try:
            enc_flag = bytes.fromhex(m.group(1).decode())
            return enc_flag
        except Exception:
            return None
    return None

# This function re-injects our recovered flag (or any plaintext) so that the service
# prints it via option 7.
def force_print_flag(p, flag_plain):
    # Option 2: encrypt our flag; sets last_operation_output = 5DES_encrypt(flag)
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'2')
    x = p.recvuntil(b'Plaintext (hex): ')
    print(x)
    p.sendline(flag_plain.hex().encode())
    x = p.recvuntil(b'Encryption succeded')
    print(x)

    # Option 5: decrypt the just-encrypted data so last_operation_output becomes flag
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'5')
    x = p.recvuntil(b'Decryption succeded')
    print(x)

    # Option 7: check last operation output; if it equals flag, the service prints it!
    x = p.recvuntil(b'> ')
    print(x)
    p.sendline(b'7')
    result = p.recvline(timeout=2)
    return result

# --- Main Exploit Flow ---
def main():
    # Connect to the remote service.
    p = remote("ccit25.havce.it", 48293)
    
    # --- Step 1. Set a known key.
    # Choose an 8-byte user key (exactly 8 bytes).
    user_key = b'\x01' * 8  
    # Choose a 40-byte plaintext for key generation.
    # Must be 5 unique chunks of 8 bytes.
    user_plain = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07' +
        b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
        b'\x10\x11\x12\x13\x14\x15\x16\x17' +
        b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' +
        b'\x20\x21\x22\x23\x24\x25\x26\x27'
    )
    set_keys(p, user_plain, user_key)
    
    # Compute the 40-byte 5DES key used by the service.
    new_key = new_5des_key(user_plain, user_key)
    ciphers = create_des5(new_key)
    
    # --- Step 2. Request flag encryption.
    encrypt_flag(p)
    
    # --- Step 3. Leak the encrypted flag.
    enc_flag = leak_encrypted_flag(p)
    if enc_flag is None:
        print("[-] Failed to leak encrypted flag. Adjust leak method!")
        p.interactive()
        return
    print("[+] Leaked encrypted flag (hex):", enc_flag.hex())
    
    # --- Step 4. Locally decrypt the flag.
    flag_plain = des5_decrypt(ciphers, enc_flag)
    try:
        flag = flag_plain.decode()
    except UnicodeDecodeError:
        flag = flag_plain.hex()
    print("[+] Recovered flag:", flag)
    
    # --- Step 5. Force the service to print the flag.
    result = force_print_flag(p, flag_plain)
    print("[+] Service response:", result.decode(errors='replace').strip())
    
    p.interactive()

if __name__=="__main__":
    main()
