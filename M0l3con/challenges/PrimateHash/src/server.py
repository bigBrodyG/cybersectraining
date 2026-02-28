import random
import string
from secret import flag

def lrot(x,y):
    return ((x<<y) | (x>>(32-y))) & 0xFFFFFFFF

def perm(data):
    round_const = [3243810922, 2109166420, 1261644, 284795533, 267721891, 1428520712, 451254836, 3023120923, 3616733408, 3544909379, 1141941182, 3419528971, 3988935951, 3469132367, 639675417, 2336458540]
    v = data[:]
    for i in range(1024):
        v[0] ^= round_const[i & 0xF]
        for j in range(16):
            t = v[j]
            t += v[j-4]
            t = t & 0xFFFFFFFF
            t = t ^ lrot(t, 21) ^ lrot(t, 3)
            t = t ^ v[j-2]
            t += v[(j+2) & 0xF]
            t = t & 0xFFFFFFFF
            t = t ^ lrot(t, 16)
            t = t ^ v[(j+1) & 0xF]
            t = t ^ round_const[j]
            v[j] = t
    return v

def custom_hash(user_input):
    data = [int.from_bytes(user_input[i:i+4], 'little') for i in range(0, len(user_input), 4)]
    s = [747420564, 1330225282, 106386925, 1126501333, 1458865636, 4100469049, 1339981680, 3086093422, 1797395789, 1644118404, 248157630, 4272628878, 1220271058, 3463197254, 2820463463, 186181749]
    datalen = len(data)
    while datalen >= 16:
        s = [s[i]^data[i] for i in range(16)]
        s = perm(s)
        datalen -= 16
        data = data[16:]
    for i in range(datalen):
        s[i] ^= data[i]
    s[datalen] ^= 1
    s = perm(s)
    h = b"".join([x.to_bytes(4, 'little') for x in s]).hex()
    return h

for _ in range(20):
    s = "".join(random.choice(string.ascii_letters) for i in range(192))
    print(s)
    s2 = bytes.fromhex(input())
    h1 = custom_hash(s.encode())
    h2 = custom_hash(s2)
    if h1 == h2 and s.encode() != s2:
        print("Yeeee")
    else:
        print("plz collide more")
        exit(0)
print(flag)
