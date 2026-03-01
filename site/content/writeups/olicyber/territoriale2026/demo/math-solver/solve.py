import re
import requests as r


url = "http://10.45.1.2:8000/"
sess = r.Session()

resp = sess.get(url)
match = re.search(r'(\d+)x \+ (\d+) = (\d+)', resp.text)
a, b, c = map(int, match.groups())
solution = round((c - b) / a, 2)
print(f"Equation: {a}x + {b} = {c}, solution: {solution}")

for i in range(100):
    r2 = sess.post(url + "solve", json={"solution": solution})
    if not r2.json().get("correct"):
        print(f"Wrong solution at iteration {i+1}")
        break

final = sess.get(url)
if "flag{" in final.text:
    flag_match = re.search(r'(flag\{.*?\})', final.text)
    if flag_match:
        print("Flag:", flag_match.group(1))
else:
    print("Flag not found. Try running again or check for errors.")


# flag{did_y0u_d0_i7_7h3_cryp70_w4y?}
