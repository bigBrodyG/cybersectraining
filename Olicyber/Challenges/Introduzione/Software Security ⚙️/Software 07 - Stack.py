string = b'\x66\xc6\x85\xf1\xfe\xff\xff\x6c\xc6\x85\xf2\xfe\xff\xff\x61\xc6\x85\xf3\xfe\xff\xff\x67\xc6\x85\xf4\xfe\xff\xff\x7b\xc6\x85\xf5\xfe\xff\xff\x66\xc6\x85\xf6\xfe\xff\xff\x63\xc6\x85\xf7\xfe\xff\xff\x32\xc6\x85\xf8\xfe\xff\xff\x66\xc6\x85\xf9\xfe\xff\xff\x34\xc6\x85\xfa\xfe\xff\xff\x34\xc6\x85\xfb\xfe\xff\xff\x39\xc6\x85\xfc\xfe\xff\xff\x62\xc6\x85\xfd\xfe\xff\xff\x7d\xc6\x85\xfe\xfe\xff\xff'

# Extract ASCII characters, ignoring errors
ascii_string = string.decode('ascii', errors='ignore')
print(ascii_string)
'''
Output: flag{fc2f449b}
'''