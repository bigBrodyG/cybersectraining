from secret import FLAG
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import choice
from Crypto.Util.number import long_to_bytes
import string

ALPHABET = string.ascii_letters + string.digits + string.punctuation
assert all([c in ALPHABET for c in FLAG])

def xor(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

class AES_CTR:
    def __init__(self, key, nonce=get_random_bytes(2), counter=0):
        self.key = key
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.nonce = nonce
        self.counter = counter

    def _update_internals(self):
        self.counter += 1
        # NOT standard, but we also change nonce every block for added security
        self.nonce = get_random_bytes(2)

    def encrypt(self, data):
        assert (len(data) % AES.block_size) == 0
        tmp = self.aes.encrypt(self.nonce + long_to_bytes(self.counter).rjust(AES.block_size - len(self.nonce), b'\x00'))
        self._update_internals()
        return xor(tmp, data)


def main():
    key = get_random_bytes(16)
    print(f'key: {key.hex()}')
    cipher = AES_CTR(key)

    enc_blocks = []
    for c in FLAG:
        padding_char = choice(ALPHABET)
        block_data = c.rjust(16, padding_char).encode()
        enc = cipher.encrypt(block_data)
        enc_blocks.append(enc.hex())
    print(f'enc_blocks: {enc_blocks}')


if __name__=='__main__':
    main()


# output
'''
key: dd2a0f3fdaa6f8b32d86038f7002109b
enc_blocks: ['1d88eacb1550bfda5bfb2bae9dae7638', '3a6f157b871a80227bdf1394d6f22bc4', '5096f828932139881696cc5e6abbc177', 'd30ba2b2c1ba2d85fa7aa560041b430e', 'd23dbf579d708e7e8bc1e66d9452a802', '151e4b639e729eb6ee6d1c170fa273d5', '35bb8fc2b7eef0ccc2dec7bfa12eab63', '6fe6390799df3377bb85617fc6eba95f', 'd7cf64b414fb238b70c24e731de4ca49', '8c70958ecdcdd266f19fd690d7f127dd', 'c495e9056da0ccaf1550480ab4e53d86', 'd788c498f16bca8b81b075b54ee0e836', 'eeb0ef1263e8d81f2406220b8db6e847', 'a171be2a31edb246bc11aeb4369cc1ea', '65acefaed0b780589cf3996e1b8e867e', '17eec0432683774905bc528cbb80de33', 'ce95a710342f128a72235d9dc07eb494', 'a754cb12d378c06d26ac4e1de163ce4d', 'f28bd906c408c57484775751c6b0249a', '2f0f0cb9231759d2c8903d87e0bbe3a1', 'deb3f72441adb8184f46e352d4fcdcc3', '76f90420715a939f9ecffcc0c8e9ecdc', '106734d7850df3826b55d9c82e22db6f', '85b5f3ba06d9cf21369128688b307135', 'c0c2cc0fe04dbc4a9cc3219398634efb', 'dd3155bc796245a8fa5968bdebdfe535', 'c4686f01e54edbf368cc77f384da1cb9', '6acd22731b7027520ed26678844685af', '3b04917a857ba84358f3ca73966c802a', 'd6391e89d7a1a4501d8e4f0cdf100903', 'f0e6cfb2a934c046907fea232c15e2e8', '84302b3dcdbd043220bfc14d0d9f3ab4', 'f169d1840ee65da021464922ef95cea1', '5a37c767dfb4ead05074d7eb323db81d', '95fab546f919de73ff572285fa20515e', '00fbf71a5b81dbd8d7f5a0758c8486cf', '20266e1dfc7b12e35ccc5231d7b4346e', 'c196df4263337738fbc02476b07be2b7', 'a69f9eafcbc3c192025043e1c4c7310c', 'd7fa736a9aceab934921f81cbeb1c4ba', '750de3d7ef2d68b916fedccf659bb784', 'ac153f5f8f5f969ff69e0a5789b5814f', '2cf16ae17444e9a4b9095a6abca4874f', 'f3b8546fa93fadafa69e3fee02365e03', '74cc7a214a07b42d68ad1fd4259e7d7c', 'e0c8beaf41000f0ea287cfb8cc5304ca', 'a5d1a4e7228578eab7f5e7dc7537d139', '6c1e3135eaa0d1cd3558730f4b01ff74']
'''