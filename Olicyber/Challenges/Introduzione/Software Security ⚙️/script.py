from pwn import *
def somma(l):
    s = 0
    for i in l:
        s += int(i)
    return s

r = remote("software-17.challs.olicyber.it", 13001)
r.recv(400)
r.sendline()
for _ in range(10):
    r.recvuntil(b" : ")
    num = (r.recvuntil(b"\n").decode().strip(' ').split(" "))[1:]
    print(num)
    r.recv(100)
    r.sendline(str(somma(num)).encode())
print(r.recv(100))