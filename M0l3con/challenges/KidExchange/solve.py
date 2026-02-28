#!/usr/bin/env python3
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PCAP = "/home/giordi/KidExchange/capture.pcapng"
M = 1 << 128


def extract_payloads(pcap_path):
    proc = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields", "-e", "tcp.payload"],
        check=True,
        capture_output=True,
        text=True,
    )
    payloads = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        payloads.append(bytes.fromhex(line))
    return payloads


def e7_from_public(p1, p2):
    return (p1 * ((p1 + 4 * p2) % M)) % M


def decrypt_aes_ecb(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def main():
    payloads = extract_payloads(PCAP)

    nums = []
    ct = None
    for payload in payloads:
        stripped = payload.rstrip(b"\n")
        if stripped.isdigit():
            nums.append(int(stripped.decode()))
        else:
            ct = payload

    if len(nums) < 4 or ct is None:
        raise RuntimeError("Failed to parse exchange from capture")

    p1_a, p2_a, p1_b, p2_b = nums[:4]

    e7_a = e7_from_public(p1_a, p2_a)
    e7_b = e7_from_public(p1_b, p2_b)
    k = pow(3, e7_a * e7_b, M)
    key = k.to_bytes(16, "big")

    pt = decrypt_aes_ecb(key, ct)
    pt = pt.rstrip(b"\x00")
    print(pt.decode())


if __name__ == "__main__":
    main()
