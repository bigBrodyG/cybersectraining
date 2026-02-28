#!/usr/bin/env python3
import socket
import re
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = 'seaside.challs.olicyber.it'
PORT = 18005

# CSIDH p512 uses 64-byte field elements.
P_BYTES = 64


def aes_ecb_decrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def solve_pow(prefix: str, suffix: str) -> str:
    counter = 0
    while True:
        candidate = f"{prefix}{counter}".encode()
        if sha256(candidate).hexdigest().endswith(suffix):
            return candidate.decode()
        counter += 1


def main():
    # The singular curve A=2 passes the supersingularity check and dh(s, A)
    # is constant for any secret s, so both shared keys are fixed.
    fixed_curve = (2).to_bytes(P_BYTES, 'little')

    with socket.create_connection((HOST, PORT)) as s:
        f = s.makefile('rwb', buffering=0)

        # Handle optional proof-of-work.
        line = f.readline().decode()
        pow_match = re.search(
            r"starting in ([A-Za-z0-9]+) .* ends in ([0-9a-fA-F]+)", line
        )
        if pow_match:
            prefix, suffix = pow_match.group(1), pow_match.group(2).lower()
            solution = solve_pow(prefix, suffix)
            f.write(solution.encode() + b"\n")
            line = f.readline().decode()

        # Read until we get Alice's curve line.
        if not line:
            raise RuntimeError('No greeting')
        m = re.search(r"Alice's curve:\s*([0-9a-fA-F]+)", line)
        if not m:
            while line:
                m = re.search(r"Alice's curve:\s*([0-9a-fA-F]+)", line)
                if m:
                    break
                line = f.readline().decode()
            if not m:
                raise RuntimeError('Alice curve not found')

        # Read prompt line
        f.readline()

        # Send the singular curve.
        f.write(fixed_curve.hex().encode() + b"\n")

        # Read ciphertext line
        ct_line = f.readline().decode()
        m = re.search(
            r"Alice's encrypted messages:\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)",
            ct_line,
        )
        if not m:
            raise RuntimeError('Ciphertexts not found')
        ct0 = bytes.fromhex(m.group(1))
        ct1 = bytes.fromhex(m.group(2))

        # Read prompt for learned messages
        f.readline()

        key = sha256(fixed_curve).digest()
        m0 = aes_ecb_decrypt(key, ct0)
        m1 = aes_ecb_decrypt(key, ct1)

        f.write(m0.hex().encode() + b" " + m1.hex().encode() + b"\n")
        result = f.readline().decode().strip()
        print(result)


if __name__ == '__main__':
    main()
