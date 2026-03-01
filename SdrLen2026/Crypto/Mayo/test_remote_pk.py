import socket
import re

def recvuntil(sock, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = sock.recv(1)
        if not chunk: break
        data += chunk
    return data

def get_pk():
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
    s.close()
    if pk_match:
        return pk_match.group(1)
    return None

pk1 = get_pk()
pk2 = get_pk()
if pk1 == pk2:
    print("Remote PK is FIXED!")
else:
    print("Remote PK is RANDOM!")
    print("PK1:", pk1[:32])
    print("PK2:", pk2[:32])
