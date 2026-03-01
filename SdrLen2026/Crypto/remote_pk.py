import socket
import re

def recvuntil(sock, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = sock.recv(1)
        if not chunk: break
        data += chunk
    return data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("mayo.challs.srdnlen.it", 1340))
recvuntil(s, b"choice: ")
s.sendall(b"1" + bytes([10]))
recvuntil(s, b"Choose the index of the byte to edit: ")
s.sendall(b"24214" + bytes([10]))
recvuntil(s, b"Choose which nibble to edit: ")
s.sendall(b"0" + bytes([10]))
recvuntil(s, b"Choose the value to write: ")
s.sendall(b"14" + bytes([10]))

out = b""
while True:
    chunk = s.recv(4096)
    if not chunk: break
    out += chunk

out = out.decode()
pk_match = re.search(r"pk:\s*([a-f0-9]+)", out)
if pk_match:
    with open("extracted_pk.txt", "w") as f:
        f.write(pk_match.group(1))
    print("Found remote PK")
else:
    print("No PK found:", out)
s.close()
