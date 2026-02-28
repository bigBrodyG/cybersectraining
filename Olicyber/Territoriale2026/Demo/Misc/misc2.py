import re
import requests as r


url = "http://10.45.1.2:8000/"
sess = r.Session()

# Step 1: Fetch the main page and get the equation
resp = sess.get(url)
match = re.search(r'(\d+)x \+ (\d+) = (\d+)', resp.text)
if not match:
    print("Equation not found!")
    exit(1)
a, b, c = map(int, match.groups())
solution = round((c - b) / a, 2)
print(f"Equation: {a}x + {b} = {c}, solution: {solution}")

# Step 2: POST the same solution 100 times
for i in range(100):
    r2 = sess.post(url + "solve", json={"solution": solution})
    if not r2.json().get("correct"):
        print(f"Wrong solution at iteration {i+1}")
        break
# Step 3: Fetch the main page to get the flag
final = sess.get(url)
if "flag{" in final.text:
    flag_match = re.search(r'(flag\{.*?\})', final.text)
    if flag_match:
        print("Flag:", flag_match.group(1))
else:
    print("Flag not found. Try running again or check for errors.")


# flag{did_y0u_d0_i7_7h3_cryp70_w4y?}
