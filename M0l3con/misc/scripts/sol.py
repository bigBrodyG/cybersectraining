import requests
import base64
from urllib.parse import quote

# Target Configuration
URL = "http://cutandpaste.chals.beginner.havce.it:1340"

def solve():
    s = requests.Session()

    # 1. Generate Prefix Block: "username=AAAAAA-"
    # "username=" (9) + "AAAAAA" (6) + "-" (1) = 16 bytes
    r1 = s.get(f"{URL}/login/AAAAAA")
    c1 = base64.b64decode(r1.cookies["id"])
    block_prefix = c1[:16]

    # 2. Generate Admin Block: "username=true" + valid padding
    # "username=" (9) + "true" (4) + "\x03"*3 (3) = 16 bytes
    # \x03 is the correct PKCS7 padding byte for 3 bytes of padding
    payload = "true" + "\x03" * 3
    r2 = s.get(f"{URL}/login/{quote(payload)}")
    c2 = base64.b64decode(r2.cookies["id"])
    block_admin = c2[:16]

    # 3. Forge Cookie
    # Structure: [username=AAAAAA-] [username=true(padded)]
    # Decrypts to: username=AAAAAA-username=true
    # App splits on '-': parts[1] becomes "username=true"
    # App splits on '=': value becomes "true" -> Admin
    forged_cookie = base64.b64encode(block_prefix + block_admin).decode()

    # 4. Extract Flag
    r_final = s.get(URL, cookies={"id": forged_cookie})
    
    if "havceCTF{" in r_final.text:
        print(r_final.text.split("FLAG: ")[1].split("<")[0])
    else:
        print("Exploit failed or flag not found in response.")
        print(r_final.text)

if __name__ == "__main__":
    solve()
