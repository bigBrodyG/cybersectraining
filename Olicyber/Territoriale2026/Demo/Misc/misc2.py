import re
import requests as r


url = "http://10.45.1.2:8000/"
sess = r.Session()

resp = sess.get(url)
mat = re.search(r'(\d+)x \+ (\d+) = (\d+)', resp.text)
a = int(mat.group(1))
b = int(mat.group(2))
c = int(mat.group(3))

solution = round((c - b) / a, 2)

for i in range(100):
    r2 = sess.post(url + "solve", json={"solution": solution})

final = sess.get(url)
print(final)

# flag{did_y0u_d0_i7_7h3_cryp70_w4y?}
