#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import string
import sys

# The allowed alphabet (from the challenge, note: string.punctuation gives all punctuation)
ALPHABET = string.ascii_letters + string.digits + string.punctuation

# Given key (hex string from the challenge output)
KEY = bytes.fromhex("dd2a0f3fdaa6f8b32d86038f7002109b")

# The list of encrypted blocks (hex strings) from the challenge output.
# (These were produced in order – one ciphertext block per flag character.)
enc_blocks_hex = [
    '1d88eacb1550bfda5bfb2bae9dae7638', '3a6f157b871a80227bdf1394d6f22bc4',
    '5096f828932139881696cc5e6abbc177', 'd30ba2b2c1ba2d85fa7aa560041b430e',
    'd23dbf579d708e7e8bc1e66d9452a802', '151e4b639e729eb6ee6d1c170fa273d5',
    '35bb8fc2b7eef0ccc2dec7bfa12eab63', '6fe6390799df3377bb85617fc6eba95f',
    'd7cf64b414fb238b70c24e731de4ca49', '8c70958ecdcdd266f19fd690d7f127dd',
    'c495e9056da0ccaf1550480ab4e53d86', 'd788c498f16bca8b81b075b54ee0e836',
    'eeb0ef1263e8d81f2406220b8db6e847', 'a171be2a31edb246bc11aeb4369cc1ea',
    '65acefaed0b780589cf3996e1b8e867e', '17eec0432683774905bc528cbb80de33',
    'ce95a710342f128a72235d9dc07eb494', 'a754cb12d378c06d26ac4e1de163ce4d',
    'f28bd906c408c57484775751c6b0249a', '2f0f0cb9231759d2c8903d87e0bbe3a1',
    'deb3f72441adb8184f46e352d4fcdcc3', '76f90420715a939f9ecffcc0c8e9ecdc',
    '106734d7850df3826b55d9c82e22db6f', '85b5f3ba06d9cf21369128688b307135',
    'c0c2cc0fe04dbc4a9cc3219398634efb', 'dd3155bc796245a8fa5968bdebdfe535',
    'c4686f01e54edbf368cc77f384da1cb9', '6acd22731b7027520ed26678844685af',
    '3b04917a857ba84358f3ca73966c802a', 'd6391e89d7a1a4501d8e4f0cdf100903',
    'f0e6cfb2a934c046907fea232c15e2e8', '84302b3dcdbd043220bfc14d0d9f3ab4',
    'f169d1840ee65da021464922ef95cea1', '5a37c767dfb4ead05074d7eb323db81d',
    '95fab546f919de73ff572285fa20515e', '00fbf71a5b81dbd8d7f5a0758c8486cf',
    '20266e1dfc7b12e35ccc5231d7b4346e', 'c196df4263337738fbc02476b07be2b7',
    'a69f9eafcbc3c192025043e1c4c7310c', 'd7fa736a9aceab934921f81cbeb1c4ba',
    '750de3d7ef2d68b916fedccf659bb784', 'ac153f5f8f5f969ff69e0a5789b5814f',
    '2cf16ae17444e9a4b9095a6abca4874f', 'f3b8546fa93fadafa69e3fee02365e03',
    '74cc7a214a07b42d68ad1fd4259e7d7c', 'e0c8beaf41000f0ea287cfb8cc5304ca',
    'a5d1a4e7228578eab7f5e7dc7537d139', '6c1e3135eaa0d1cd3558730f4b01ff74'
]

# Convert ciphertext blocks from hex to bytes.
cipher_blocks = [bytes.fromhex(c) for c in enc_blocks_hex]

# Our decryption method uses the fact that each plaintext block M is:
#    M = p * 15 || c
# where p is the 15-byte padding character (all identical) and c is the flag character.
# For each block, we try all 2^16 possible 2-byte nonces.
def decrypt_block(block, counter):
    # For the counter, we need its 14-byte representation.
    # Use long_to_bytes and then pad (rjust) to 14 bytes.
    counter_bytes = long_to_bytes(counter).rjust(14, b'\x00')
    cipher_aes = AES.new(KEY, AES.MODE_ECB)
    # Brute-force candidate nonces (2 bytes each).
    for nonce_candidate in range(0, 1 << 16):
        nonce = nonce_candidate.to_bytes(2, "big")
        # Build the 16-byte input for AES: nonce || counter_bytes
        keystream_input = nonce + counter_bytes
        keystream = cipher_aes.encrypt(keystream_input)
        # The plaintext block is the XOR of keystream and the ciphertext block.
        plaintext = bytes([a ^ b for a, b in zip(keystream, block)])
        # Check if the structure matches:
        #   first 15 bytes must be identical (i.e. a repeated padding character) and in ALPHABET,
        #   and the 16th byte must also be in ALPHABET.
        pad = plaintext[0]
        if all(b == pad for b in plaintext[:15]):
            # Convert pad and the last byte to characters.
            try:
                pad_char = chr(pad)
                flag_char = chr(plaintext[15])
            except Exception:
                continue
            if (pad_char in ALPHABET) and (flag_char in ALPHABET):
                return flag_char  # We return the flag character for this block.
    # If no candidate nonce worked, indicate failure.
    print(f"Could not decrypt block with counter {counter}", file=sys.stderr)
    return "?"  # Placeholder

def main():
    flag = ""
    for idx, block in enumerate(cipher_blocks):
        sys.stdout.write(f"Processing block {idx}...\n")
        flag_char = decrypt_block(block, idx)
        flag += flag_char
    print("\nFlag:", "CCIT2024{" + flag + "}")

if __name__=='__main__':
    main()
