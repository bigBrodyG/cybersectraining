try:
    from Crypto.Cipher import AES
    print('pycryptodome ok')
except Exception as e:
    print('no Crypto', e)
try:
    import z3
    print('z3 ok')
except Exception as e:
    print('no z3', e)
