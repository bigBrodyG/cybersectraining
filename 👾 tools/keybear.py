import sys
try:
    from pyautogui import *
except:
    print("PyAutoGui not found. Downloading...")
    import os
    os.system("pip install pyautogui")
    from pyautogui import *

file = sys.argv
print(file)
if len(file) != 2:
    print("Usage: python keybear.py <file>")
    sys.exit(1)
file = file[1]


with open(file, errors='ignore') as f:
    print("Reading file...")
    f = f.read()
    typewrite(f)
