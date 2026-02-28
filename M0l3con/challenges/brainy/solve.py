from pwn import *

# Context setup
context.log_level = 'info'

def generate_bf(target):
    code = ""
    current = 0
    for char in target:
        val = ord(char)
        diff = val - current
        if diff > 0:
            code += "+" * diff
        elif diff < 0:
            code += "-" * abs(diff)
        code += "."
        current = val
    return code

def solve():
    conn = remote('brainy.chals.beginner.havce.it', 1339)
    
    # Read until the prompt for the string
    try:
        conn.recvuntil(b"stampi la seguente stringa: ")
        
        # The next part should be the string. It might be followed by a newline or just sitting there.
        # Since it's a CLI challenge, it likely prints the string and waits for input on a new line or same line.
        # Based on previous output: "... stringa: WFLAQDOEARNYQJU"
        # It looks like the string is immediately following.
        
        target_string = conn.recvline().decode().strip()
        print(f"Target String extracted: '{target_string}'")
        
        bf_code = generate_bf(target_string)
        print(f"Sending BF code (len {len(bf_code)})...")
        
        conn.sendline(bf_code.encode())
        
        # Read response (Flag)
        response = conn.recvall(timeout=5).decode()
        print("Server Response:\n", response)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    solve()

