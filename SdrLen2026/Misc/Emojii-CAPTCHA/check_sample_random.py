import re
import socket


def recv_until(sock, marker: bytes, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data


def recv_more(sock, timeout=1.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 8192:
                break
    except Exception:
        pass
    return data


s = socket.create_connection(("emoji.challs.srdnlen.it", 1717), timeout=10)
_ = recv_until(s, b"> ")

all_data = []
for _ in range(3):
    s.sendall(b"1\n")
    data = recv_until(s, b"> ", timeout=10) + recv_more(s, timeout=0.5)
    text = data.decode(errors="ignore")
    all_data.append(text)

for i, text in enumerate(all_data, 1):
    m = re.search(r"Here is your CAPTCHA:\n([A-Za-z0-9+/=]+)", text)
    e = re.search(r"Expected solution for the sample CAPTCHA:\s*(.+)", text)
    b64 = m.group(1) if m else ""
    exp = e.group(1).strip() if e else ""
    print(i, len(b64), b64[:80], exp)

print("same12", all_data[0] == all_data[1])
print("same23", all_data[1] == all_data[2])
