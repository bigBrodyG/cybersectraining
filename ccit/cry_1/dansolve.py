#!/usr/bin/env python3
from pwn import remote
import sys

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def forge_ticket(available_ticket_hex: str, known_plaintext: str, secret_plaintext: str) -> str:
    """
    Given a ticket (hex string) for a known song, forge a new ticket so that its decryption
    is the secret_plaintext.
    
    The ticket format is: nonce (8 bytes) || ciphertext.
    """
    ticket_bytes = bytes.fromhex(available_ticket_hex)
    if len(ticket_bytes) < 8:
        raise ValueError("Ticket is too short!")

    nonce = ticket_bytes[:8]
    ciphertext = ticket_bytes[8:]
    n = len(secret_plaintext)  # We need keystream for the length of the secret song.

    if len(known_plaintext) < n or len(ciphertext) < n:
        raise ValueError("Not enough ticket data to forge secret message.")

    known_pt_prefix = known_plaintext.encode()[:n]
    known_ct_prefix = ciphertext[:n]
    keystream_prefix = xor_bytes(known_ct_prefix, known_pt_prefix)
    forged_ct = xor_bytes(secret_plaintext.encode(), keystream_prefix)
    forged_ticket = nonce + forged_ct
    return forged_ticket.hex()

def main():
    # Connect to the remote challenge server.
    p = remote('ccit25.havce.it', 48294)
    
    # Wait until the prompt appears.
    p.recvuntil(b'> ')
    
    # Choose option 3 for "Jessica Jay - Chilly Cha Cha" to get a valid ticket.
    # (Option indexes start at 0, so option 3 gives us the fourth song.)
    p.sendline(b'3')
    
    # The program prints a line like:
    # This is your ticket: <ticket_hex>
    ticket_line = p.recvline().strip()
    print(ticket_line)
    if b'ticket:' not in ticket_line:
        sys.exit("[-] Failed to retrieve a ticket!")
    
    # Extract the ticket hex (everything after the colon).
    ticket_hex = ticket_line.split(b':')[-1].strip().decode()
    print(f"[+] Received ticket: {ticket_hex}")
    
    # Known song plaintext corresponding to option 3:
    known_plaintext = "Jessica Jay - Chilly Cha Cha"
    # Secret song that will trigger the flag (must be exactly 23 bytes):
    secret_plaintext = "Freddie Dredd - Cha Cha"
    
    # Forge a new ticket using the known ticket.
    forged_ticket = forge_ticket(ticket_hex, known_plaintext, secret_plaintext)
    print(f"[+] Forged ticket: {forged_ticket}")
    
    # Now select the "Play song" option (option index 5) to play the forged ticket.
    p.recvuntil(b'> ')
    p.sendline(b'5')
    
    # When prompted for the ticket, send the forged ticket.
    p.recvuntil(b'Ticket (hex): ')
    p.sendline(forged_ticket.encode())
    
    # Receive all output (which should include the flag if successful).
    result = p.recvall(timeout=5)
    print(result.decode())

if __name__ == '__main__':
    main()
