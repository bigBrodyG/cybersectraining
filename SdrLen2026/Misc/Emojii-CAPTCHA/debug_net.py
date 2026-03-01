from pwn import *

r = remote('emoji.challs.srdnlen.it', 1717)
r.recvuntil(b'> ')
r.sendline(b'2')

print("Starting to read raw bytes...")
try:
    data = r.recv(4096, timeout=5)
    print(f"Received chunk 1: {len(data)} bytes")
    
    data2 = r.recv(409600, timeout=5)
    print(f"Received chunk 2: {len(data2)} bytes")
    
    with open('raw_dump.txt', 'wb') as f:
        f.write(data)
        f.write(data2)
        
    print("Saved to raw_dump.txt")
except Exception as e:
    print(f"Exception: {e}")
