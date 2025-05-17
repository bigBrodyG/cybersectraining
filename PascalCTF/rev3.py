import requests

url = "https://kontactmi.challs.pascalctf.it/adminSupport"
payload = {"code": "255"}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=payload, headers=headers)
print("Status code:", response.status_code)
print("Response text:", response.text)