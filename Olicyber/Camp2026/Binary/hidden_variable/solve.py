from pwn import *

elf = ELF("./hidden_variable")
flag_data = elf.read(elf.symbols["fl4g"], 256)
flag = flag_data[::4].split(b"\x00")[0].decode("utf-8")
print(f"Flag is: {flag}")
