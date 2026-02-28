import socket
import re
import random
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "lazy-platform.challs.olicyber.it"
PORT = 16004


@dataclass
class SockReader:
    sock: socket.socket
    buf: bytes = b""

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("Connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out


def unshift_right_xor(y, shift):
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF


def unshift_left_xor_mask(y, shift, mask):
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(y):
    y = unshift_right_xor(y, 18)
    y = unshift_left_xor_mask(y, 15, 0xefc60000)
    y = unshift_left_xor_mask(y, 7, 0x9d2c5680)
    y = unshift_right_xor(y, 11)
    return y


def words_from_hex(hexstr: str) -> list[int]:
    data = bytes.fromhex(hexstr)
    if len(data) % 4 != 0:
        raise ValueError("length not multiple of 4")
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]


def decrypt_aes_cbc(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    pad_len = pt[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("bad padding")
    if pt[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding")
    return pt[:-pad_len]


def main():
    with socket.create_connection((HOST, PORT)) as sock:
        r = SockReader(sock)

        # initial menu prompt
        r.recv_until(b"> ")

        outputs = []
        rounds = 52  # 52 * 12 = 624
        for _ in range(rounds):
            sock.sendall(b"1\n")
            r.recv_until(b"Enter a message to encrypt: ")
            sock.sendall(b"A\n")
            data = r.recv_until(b"> ")
            text = data.decode("ascii", errors="ignore")
            m = re.search(r"Key: ([0-9a-f]+)\nIV: ([0-9a-f]+)", text)
            if not m:
                raise RuntimeError("failed to parse key/iv")
            key_hex, iv_hex = m.group(1), m.group(2)
            outputs.extend(words_from_hex(key_hex))
            outputs.extend(words_from_hex(iv_hex))

        if len(outputs) != 624:
            raise RuntimeError(f"expected 624 outputs, got {len(outputs)}")

        state = [untemper(o) for o in outputs]
        clone = random.Random()
        clone.setstate((3, tuple(state + [624]), None))

        # request flag ciphertext
        sock.sendall(b"3\n")
        data = r.recv_until(b"> ")
        text = data.decode("ascii", errors="ignore")
        m = re.search(r"Ciphertext: ([0-9a-f]+)", text)
        if not m:
            raise RuntimeError("failed to parse ciphertext")
        ct = bytes.fromhex(m.group(1))

        key_words = [clone.getrandbits(32) for _ in range(8)]
        iv_words = [clone.getrandbits(32) for _ in range(4)]
        key = b"".join(w.to_bytes(4, "little") for w in key_words)
        iv = b"".join(w.to_bytes(4, "little") for w in iv_words)

        pt = decrypt_aes_cbc(key, iv, ct)
        print(pt.decode("ascii", errors="replace"))


if __name__ == "__main__":
    main()
