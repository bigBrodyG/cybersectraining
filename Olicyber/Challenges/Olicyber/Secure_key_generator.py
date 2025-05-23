#!/usr/bin/env python3

from hashlib import sha256
from datetime import datetime
import random

# The timestamp from the comment in the original script
TARGET_DATETIME_STR = "2021-03-21 17:37:40"

def int_to_bytes(x):
    # Ensure x is non-negative for bit_length calculation if it could be negative
    if x < 0:
        # This case needs specific handling if negative numbers are expected
        # For timestamps, it's usually positive.
        raise ValueError("Timestamp cannot be negative for this conversion")
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes):
    # If the byte string is empty, the original int.from_bytes would error.
    # We'll assume for the CTF's sake, this leads to a seed of 0.
    if not xbytes:
        return 0
    return int.from_bytes(xbytes, 'big')

def generate_vulnerable_key():
    # Convert the target datetime string to a datetime object
    dt_obj = datetime.strptime(TARGET_DATETIME_STR, "%Y-%m-%d %H:%M:%S")
    # Get the Unix timestamp as an integer
    ts = int(datetime.timestamp(dt_obj))
    
    h = sha256(int_to_bytes(ts)).digest()

    # Flawed part: h[32:] results in an empty byte string because h is 32 bytes long.
    seed_bytes_from_hash = h[32:] # This will be b''
    
    # int_from_bytes(b'') will return 0 with our modified helper.
    # In the original, it would raise a ValueError. If not handled, script crashes.
    # If handled by try-except setting seed to 0, then random.seed(0) is used.
    # If random.seed() is called with no argument (due to error), it might use system time,
    # but for a CTF, a predictable outcome is more likely. We assume seed becomes 0.
    seed_for_prng = int_from_bytes(seed_bytes_from_hash) 
                                   
    key_part1 = h[:32] # The first 32 bytes are the SHA256 hash itself.
    
    key = key_part1 # Initialize key with the hash part
    
    random.seed(seed_for_prng) # Effectively random.seed(0)
    
    key_part2 = b""
    for _ in range(32):
        key_part2 += bytes([random.randint(0, 255)])
    
    final_key = key_part1 + key_part2 # Total 64 bytes
    return final_key

def xor_decrypt(encrypted_data, key):
    decrypted = bytearray()
    for i in range(len(encrypted_data)):
        decrypted.append(encrypted_data[i] ^ key[i % len(key)])
    return bytes(decrypted)

# --- Main execution ---
if __name__ == "__main__":
    print(f"[*] Using target timestamp: {TARGET_DATETIME_STR}")
    
    # Regenerate the key
    key = generate_vulnerable_key()
    print(f"[*] Regenerated Key (first 16 bytes): {key[:16].hex()}...")
    print(f"[*] Key Length: {len(key)} bytes")

    # Attempt to decrypt 'flag.enc'
    # The user needs to provide the 'flag.enc' file.
    encrypted_file_name = "flag.enc" # Assuming this is the file name
    decrypted_file_name = "flag.dec"

    try:
        with open(encrypted_file_name, "rb") as f:
            encrypted_content = f.read()
        
        print(f"[*] Read {len(encrypted_content)} bytes from {encrypted_file_name}")
        
        decrypted_content = xor_decrypt(encrypted_content, key)
        
        print(f"[*] Decryption complete.")
        
        # Try to decode as text, otherwise save as binary
        try:
            flag_text = decrypted_content.decode('utf-8')
            print("\n--- FLAG ---")
            print(flag_text)
            print("------------")
        except UnicodeDecodeError:
            print(f"[*] Decrypted content is not valid UTF-8. Saving to {decrypted_file_name}")
            with open(decrypted_file_name, "wb") as f_out:
                f_out.write(decrypted_content)
            print(f"[*] Decrypted binary content saved to: {decrypted_file_name}")
            print(f"[*] First 100 bytes (hex): {decrypted_content[:100].hex()}")

    except FileNotFoundError:
        print(f"[!] Error: Encrypted file '{encrypted_file_name}' not found.")
        print(f"    Please place the encrypted file in the same directory as this script.")
    except Exception as e:
        print(f"[!] An error occurred during decryption: {e}")
