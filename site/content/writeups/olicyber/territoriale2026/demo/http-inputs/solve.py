import requests

url = "http://10.45.1.2:4001/?we_like=flags"
headers = {
    "give-me": "the-flag",
    "Content-Type": "text/plain"
}
cookies = {
    "session_id": "the_session"
}
data = "pretty please :("

print(f"Sending OPTIONS request to {url}")
response = requests.options(url, headers=headers, cookies=cookies, data=data)

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

# flag{puTt1Ng_t0g3tH3r_4Ll_hTtP_1npUtS_bc7f984f}
