import os
import socket
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from z3 import BitVec, BitVecVal, Solver, LShR, If, sat
from sage.all import *

# Load Castryck-Decru implementation (expects cwd inside repo)
import os as _os
_BASE_DIR = _os.path.dirname(_os.path.abspath(__file__))
_os.chdir(_os.path.join(_BASE_DIR, "castryck-decru"))
import sys as _sys
_sys.path.insert(0, _os.getcwd())
load("castryck_decru_shortcut.sage")

HOST = os.environ.get("HOST", "elliptic-pizza.challs.olicyber.it")
PORT = int(os.environ.get("PORT", "16012"))

# SIDH params
lA, a, lB, b = 2, 91, 3, 57
p = lA**a * lB**b - 1
_R = PolynomialRing(GF(p), 'x')
_x = _R.gen()
Fp2 = GF(p**2, modulus=_x**2 + 1, name='i')
i = Fp2.gen()


def generate_distortion_map(E):
    return E.isogeny(E.lift_x(ZZ(1)), codomain=E)


def compute_final_curve(E, priv_key, P, Q):
    K = P + priv_key * Q
    phi = E.isogeny(K, algorithm="factored")
    E_final = phi.codomain()
    return E_final.j_invariant()


def curve_from_str(curve_str: str):
    if " over " in curve_str:
        curve_str = curve_str.split(" over ")[0]
    rhs = curve_str.split("= ", 1)[1]
    R = PolynomialRing(Fp2, 'x')
    x = R.gen()
    poly = sage_eval(rhs, locals={'i': i, 'x': x})
    a2 = poly.coefficient(x**2)
    a4 = poly.coefficient(x)
    a6 = poly.constant_coefficient()
    return EllipticCurve(Fp2, [0, a2, 0, a4, a6])


def point_from_str(point_str: str, E):
    split_str = point_str.split('(')[1].split(')')[0].split(" : ")
    x = eval(split_str[0])
    y = eval(split_str[1])
    return E([x, y])


def split_in_words(random_number, num_of_words):
    words = []
    for _ in range(num_of_words):
        words.append(bin(random_number & 0xffffffff)[2:].zfill(32))
        random_number >>= 32
    return words


def encrypt_message(plaintext, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return (iv + ciphertext).hex()


def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


def elem_to_list(n):
    try:
        return [int(n), 0]
    except Exception:
        coefs = n.polynomial().coefficients(sparse=False)
        if len(coefs) == 1:
            return [int(coefs[0]), 0]
        return [int(coefs[0]), int(coefs[1])]


def attack(E_start, P2, Q2, P3, Q3, EA, PA, QA, EB, PB, QB):
    two_i = generate_distortion_map(E_start)

    x = PB.weil_pairing(QB, 2**a)
    base = P2.weil_pairing(Q2, 2**a)
    sol = log(x, base)
    sol = Zmod(2**a)(3**b)**-1 * sol
    possible_bs = sol.nth_root(2, all=True)

    for hope in possible_bs:
        try:
            inv = int(Zmod(2**a)(hope)**-1)
            origin_PB = inv * PB
            origin_QB = inv * QB
            priv_B = CastryckDecruAttack(E_start, P2, Q2, EB, origin_PB, origin_QB, two_i, num_cores=1)
            j = compute_final_curve(EA, priv_B, PA, QA)
            shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length() // 8 + 1, "big")
            key = sha256(shared).digest()
            return priv_B, key
        except Exception:
            continue
    raise RuntimeError("Castryck-Decru attack failed")


# Mersenne Twister recovery with partial outputs
A_CONST = BitVecVal(0x9908B0DF, 32)
UPPER_MASK = BitVecVal(0x80000000, 32)
LOWER_MASK = BitVecVal(0x7FFFFFFF, 32)


def temper(x):
    y = x
    y = y ^ LShR(y, 11)
    y = y ^ ((y << 7) & BitVecVal(0x9D2C5680, 32))
    y = y ^ ((y << 15) & BitVecVal(0xEFC60000, 32))
    y = y ^ LShR(y, 18)
    return y


def twist(state):
    new_state = []
    for i_idx in range(624):
        y = (state[i_idx] & UPPER_MASK) | (state[(i_idx + 1) % 624] & LOWER_MASK)
        x = state[(i_idx + 397) % 624] ^ LShR(y, 1)
        x = If((y & 1) == 1, x ^ A_CONST, x)
        new_state.append(x)
    return new_state


def add_constraints(solver, y, bits):
    for i_idx, ch in enumerate(bits):
        if ch == '?':
            continue
        bit = int(ch)
        solver.add((LShR(y, 31 - i_idx) & 1) == bit)


def recover_state(words):
    solver = Solver()
    state = [BitVec(f"state_{i_idx}", 32) for i_idx in range(624)]
    idx = 0
    for word in words:
        if idx == 624:
            state = twist(state)
            idx = 0
        y = temper(state[idx])
        add_constraints(solver, y, word)
        idx += 1
    if solver.check() != sat:
        raise RuntimeError("MT state recovery failed")
    model = solver.model()
    solved_state = [model.eval(v).as_long() & 0xffffffff for v in state]
    return solved_state, idx


class Remote:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(30)
        self.buf = b""

    def _recv(self, n=4096):
        chunk = self.sock.recv(n)
        if not chunk:
            raise EOFError("connection closed")
        return chunk

    def recvuntil(self, delim: bytes):
        while delim not in self.buf:
            self.buf += self._recv()
        idx = self.buf.index(delim) + len(delim)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recvline(self):
        return self.recvuntil(b"\n")

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")



def recvline_str(r: Remote):
    return r.recvline().decode().rstrip("\n")


def read_line_starting(r: Remote, prefix: str):
    while True:
        line = recvline_str(r)
        if line.startswith(prefix):
            return line


def decrypt_conversation(r: Remote, key):
    words = []
    r.recvuntil(b"> ")
    r.sendline("2")
    recvline_str(r)  # [Sorbillo] Prove me you are a true Italian!

    for _ in range(29):
        recvline_str(r)  # Compute A...
        recvline_str(r)  # Ax
        recvline_str(r)  # Ay
        line = recvline_str(r)  # Send me r / r + key
        cipher_hex = line.split()[-1]
        plain = decrypt_message(bytes.fromhex(cipher_hex), key)
        line = recvline_str(r)  # Italiano response
        cipher_hex = line.split()[-1]
        if plain == "Send me r: ":
            r_val = int(decrypt_message(bytes.fromhex(cipher_hex), key))
            words.extend(split_in_words(r_val, 8))
            coin_word = "0" + "?" * 31
        else:
            for _ in range(8):
                words.append("?" * 32)
            coin_word = "1" + "?" * 31
        recvline_str(r)  # You are X% italian
        words.append(coin_word)

    recvline_str(r)  # Oh no, the pasta is ready...
    return words


def get_words(r: Remote, key, min_known=1400):
    words = []
    while len([w for w in words if '?' not in w]) < min_known:
        words.extend(decrypt_conversation(r, key))
        known = len([w for w in words if '?' not in w])
        print(f"[+] Known words: {known}")
    return words


def main():
    r = Remote(HOST, PORT)

    # Skip intro lines until italian_G/pub_key
    read_line_starting(r, "italian_E = ")
    italian_G_line = read_line_starting(r, "italian_G = ")
    italian_pub_line = read_line_starting(r, "italian_pub_key = ")

    italian_p = 2**255 - 19
    italian_Fp = GF(italian_p)
    italian_E = EllipticCurve(italian_Fp, [0, 486662, 0, 1, 0])
    italian_G = point_from_str(italian_G_line.split("= ", 1)[1], italian_E)
    italian_pub_key = point_from_str(italian_pub_line.split("= ", 1)[1], italian_E)

    E_start_line = read_line_starting(r, "E_start = ")
    E_start = curve_from_str(E_start_line.split("= ", 1)[1])
    P2 = point_from_str(read_line_starting(r, "P2 = ").split("= ", 1)[1], E_start)
    Q2 = point_from_str(read_line_starting(r, "Q2 = ").split("= ", 1)[1], E_start)
    P3 = point_from_str(read_line_starting(r, "P3 = ").split("= ", 1)[1], E_start)
    Q3 = point_from_str(read_line_starting(r, "Q3 = ").split("= ", 1)[1], E_start)
    globals()["P3"] = P3
    globals()["Q3"] = Q3

    # Intercepted key exchange
    EA = curve_from_str(read_line_starting(r, "[Sorbillo] EA = ").split("= ", 1)[1])
    PA = point_from_str(read_line_starting(r, "[Sorbillo] PA = ").split("= ", 1)[1], EA)
    QA = point_from_str(read_line_starting(r, "[Sorbillo] QA = ").split("= ", 1)[1], EA)

    EB = curve_from_str(read_line_starting(r, "[Italiano] EB = ").split("= ", 1)[1])
    PB = point_from_str(read_line_starting(r, "[Italiano] PB = ").split("= ", 1)[1], EB)
    QB = point_from_str(read_line_starting(r, "[Italiano] QB = ").split("= ", 1)[1], EB)

    priv_B, key = attack(E_start, P2, Q2, P3, Q3, EA, PA, QA, EB, PB, QB)

    # Build word list for MT recovery
    words = []
    for _ in range(4):
        words.append("?" * 32)  # sorbillo priv_key and _a
    words.extend(split_in_words(priv_B, 2))
    for _ in range(2):
        words.append("?" * 32)  # _b

    words.extend(get_words(r, key))

    state, idx = recover_state(words)

    import random as pyrandom
    rand = pyrandom.Random()
    rand.setstate((3, tuple(state + [idx]), None))

    # Order pizza
    r.recvuntil(b"> ")
    r.sendline("1")

    priv_sorbillo = rand.getrandbits(64)
    _a = 3 * rand.getrandbits(64) + 1

    K = P2 + priv_sorbillo * Q2
    phi = E_start.isogeny(K, algorithm="factored")
    EA = phi.codomain()
    PA, QA = _a * phi(P3), _a * phi(Q3)

    # Send our EB and points with a fixed priv_key
    priv_key = 1337
    K = P3 + priv_key * Q3
    phi = E_start.isogeny(K, algorithm="factored")
    EB = phi.codomain()

    r.recvuntil(b"a1_1: ")
    a1_2, a1_1 = elem_to_list(EB.a1())
    a2_2, a2_1 = elem_to_list(EB.a2())
    a3_2, a3_1 = elem_to_list(EB.a3())
    a4_2, a4_1 = elem_to_list(EB.a4())
    a6_2, a6_1 = elem_to_list(EB.a6())

    r.sendline(str(a1_1))
    r.recvuntil(b"a1_2: ")
    r.sendline(str(a1_2))
    r.recvuntil(b"a2_1: ")
    r.sendline(str(a2_1))
    r.recvuntil(b"a2_2: ")
    r.sendline(str(a2_2))
    r.recvuntil(b"a3_1: ")
    r.sendline(str(a3_1))
    r.recvuntil(b"a3_2: ")
    r.sendline(str(a3_2))
    r.recvuntil(b"a4_1: ")
    r.sendline(str(a4_1))
    r.recvuntil(b"a4_2: ")
    r.sendline(str(a4_2))
    r.recvuntil(b"a6_1: ")
    r.sendline(str(a6_1))
    r.recvuntil(b"a6_2: ")
    r.sendline(str(a6_2))

    PB, QB = phi(P2), phi(Q2)
    xP_2, xP_1 = elem_to_list(PB[0])
    yP_2, yP_1 = elem_to_list(PB[1])
    xQ_2, xQ_1 = elem_to_list(QB[0])
    yQ_2, yQ_1 = elem_to_list(QB[1])

    r.recvuntil(b"xP_1: ")
    r.sendline(str(xP_1))
    r.recvuntil(b"xP_2: ")
    r.sendline(str(xP_2))
    r.recvuntil(b"yP_1: ")
    r.sendline(str(yP_1))
    r.recvuntil(b"yP_2: ")
    r.sendline(str(yP_2))
    r.recvuntil(b"xQ_1: ")
    r.sendline(str(xQ_1))
    r.recvuntil(b"xQ_2: ")
    r.sendline(str(xQ_2))
    r.recvuntil(b"yQ_1: ")
    r.sendline(str(yQ_1))
    r.recvuntil(b"yQ_2: ")
    r.sendline(str(yQ_2))

    j = compute_final_curve(EA, priv_key, PA, QA)
    shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length() // 8 + 1, "big")
    key = sha256(shared).digest()

    r.recvline()
    for _ in range(30):
        r.recvline()
        coin = rand.getrandbits(1)
        if coin:
            A = -italian_pub_key + 1337 * italian_G
        else:
            A = 1337 * italian_G
        r.recvline()
        r.sendline(encrypt_message(str(A[0]).encode(), key))
        r.recvline()
        r.sendline(encrypt_message(str(A[1]).encode(), key))
        r.recvline()
        r.sendline(encrypt_message(b"1337", key))
        print(decrypt_message(bytes.fromhex(recvline_str(r)), key))

    ciphertext = bytes.fromhex(recvline_str(r))
    flag_plain = decrypt_message(ciphertext, key)
    print(flag_plain)


if __name__ == "__main__":
    main()
