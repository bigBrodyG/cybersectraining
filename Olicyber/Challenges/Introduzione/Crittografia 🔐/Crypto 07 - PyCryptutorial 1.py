from Crypto.Cipher import DES, AES, ChaCha20
from Crypto.Util.Padding import *
from Crypto import Random

plain = "La lunghezza di questa frase non è divisibile per 8".encode("utf-8") # da cambiare
cipher = DES.new(bytes.fromhex("6a847c1e70b86f3a"), DES.MODE_CBC) # da cambiare
r = cipher.iv
f = cipher.encrypt(pad(plain, 8, "x923"))
print(f.hex())
print(r.hex())


s = Random.get_random_bytes(32)
print(s.hex())
plain = b'Mi chiedo cosa significhi il numero nel nome di questo algoritmo.'
cipher = AES.new(s, AES.MODE_CFB, segment_size=24)
f = cipher.encrypt(pad(plain, 16, "pkcs7"))
print(cipher.iv.hex())
print(f.hex())

key = bytes.fromhex("9be1b33cb46cbd7599cab735196c595dbf4b0a24e70cbb78e56a04480cea9b23")
cipher = bytes.fromhex("521480d4b7bdf08b4c347e95263aa781d8616d174ce693aca3941102")
nonce = bytes.fromhex("0256ecf1c7edf006")
s = ChaCha20.new(key=key, nonce=nonce)
print(s.decrypt(cipher).decode())