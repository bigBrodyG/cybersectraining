from z3 import *
from pwn import *

x = BitVec('x', 32)
y = BitVec('y', 32)
z = BitVec('z', 32)

shift_num = (x % y) & 0x1F
num = (x + y + z) << shift_num
shift_denom = x & 0x1F
denom = ((2 << shift_denom) ^ 3) * z

s = Solver()
s.add(y != 0, z != 0, denom != 0)
s.add(num / denom == 0xA4C570)
s.add(x >= 0, y >= 0, z >= 0)

if s.check() != sat:
    exit(1)

model = s.model()
p1 = model[x].as_long()
p2 = model[y].as_long()
p3 = model[z].as_long()

log.success(f"Found valid params: {hex(p1)}, {hex(p2)}, {hex(p3)}")

HOST = "timesup.pwn.ccit25.chals.havce.it"
PORT = 1343
r = remote(HOST, PORT)

banner = r.recvuntil(b">>>").decode()
print(banner)

import re
match = re.search(r"Current Time Is: (\d+):(\d+):(\d+)", banner)
if not match:
    print("❌ Failed to parse time from banner")
    r.close()
    exit(1)

hour, minute, second = map(int, match.groups())
print(f"[i] Server Time: {hour:02}:{minute:02}:{second:02}")

payload = f"{p1:x} {p2:x} {p3:x}\n"
r.send(payload.encode())

r.interactive()
