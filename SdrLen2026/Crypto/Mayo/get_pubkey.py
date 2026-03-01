import subprocess
import re

proc = subprocess.Popen(["python3", "server.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
out, err = proc.communicate("1\n24214\n0\n14\n")

pk_match = re.search(r"pk:\s*([a-f0-9]+)", out)
if pk_match:
    with open("extracted_pk.txt", "w") as f:
        f.write(pk_match.group(1))
    print("Found PK")
else:
    print("No PK found. Output:", out)
