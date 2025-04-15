#!/usr/local/bin/python

import os
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

FLAG = os.getenv("FLAG")
assert len(FLAG) % DES.block_size == 0

class DES5:
    _ENCRYPT_MODE = 0
    _DECRYPT_MODE = 1
    _OPERATIONS_COUNT = 5

    def __init__(self):
        self.saved_encrypted_flag = b''
        self.last_operation_output = b''
        self.ciphers = []
        self.set_key(get_random_bytes(DES.key_size*DES5._OPERATIONS_COUNT))

    def _apply_operation(self, data, mode):
        index_range = list(range(DES5._OPERATIONS_COUNT))
        if(mode == self._DECRYPT_MODE):
            index_range.reverse()

        tmp = data
        for i in index_range:
            if(i%2 == mode):
                tmp = self.ciphers[i].encrypt(tmp)
            else:
                tmp = self.ciphers[i].decrypt(tmp)

        self.last_operation_output = tmp

    def set_key(self, key):
        # delete current ciphers
        self.ciphers.clear()

        # generate new batch of ciphers with the provided key
        for i in range(DES5._OPERATIONS_COUNT):
            self.ciphers.append(DES.new(key[DES.key_size*i:DES.key_size*(i+1)], DES.MODE_ECB))

    def encrypt(self, pt):
        self._apply_operation(pt, self._ENCRYPT_MODE)

    def encrypt_flag(self):
        self.encrypt(FLAG.encode())
        self.saved_encrypted_flag = self.last_operation_output

    def encrypt_last_operation_output(self):
        self.encrypt(self.last_operation_output)

    def decrypt(self):
        if(self.last_operation_output == self.saved_encrypted_flag):
            return False

        self._apply_operation(self.last_operation_output, self._DECRYPT_MODE)
        return True


def banner():
    print()
    print('1. set keys')
    print('2. encrypt')
    print('3. encrypt flag')
    print('4. encrypt last operation output')
    print('5. decrypt')
    print('6. decrypt flag')
    print('7. check last operation output')
    print('8. exit')


def main():
    # initialize here 5DES object, with a TRUE random key
    cipher_5DES = DES5()

    print('Welcome to the 5DES demo, feel free to try what you want :)')
    while(True):
        banner()
        choice = input('> ')

        match choice:
            case '1':
                # this choice allows you to set a new key for the 5DES cipher, starting from
                # the plaintext provided and encrypting it twice. I'm so sure about the
                # security of my cipher that I allow you to also choose the key...

                try:
                    plaintext = bytes.fromhex(input('Plaintext (hex): '))
                    key = bytes.fromhex(input('Key (hex): '))
                except ValueError:
                    print('Provide an hexadecimal string!')
                    continue

                if(len(key) != DES.key_size):
                    print(f'Provide an {DES.key_size} bytes key!')
                    continue

                if(len(plaintext) != DES.key_size*DES5._OPERATIONS_COUNT):
                    print(f'Provide a {DES.key_size*DES5._OPERATIONS_COUNT} bytes plaintext to generate the new 5DES key!')
                    continue

                # check for plaintext repetitions, i don't like them :(
                plaintext_chunks = [plaintext[DES.block_size*i:DES.block_size*(i+1)] for i in range(DES5._OPERATIONS_COUNT)]
                if(len(plaintext_chunks) != len(set(plaintext_chunks))):
                    print('Repetition occurred inside the plaintext, i\'m not happy with that :(')
                    continue

                # check for repetitions of the key in the plaintext chunks
                if(key in plaintext_chunks):
                    print('To provide maximum security, overlaps between the key and the plaintext are not allowed')
                    continue

                # encrypt 2 times with DES, because more is better ;)
                cipher = DES.new(key, DES.MODE_ECB)
                tmp = cipher.encrypt(plaintext)
                new_5DES_key = cipher.encrypt(tmp)

                # set the new key to the 5DES cipher
                cipher_5DES.set_key(new_5DES_key)

                print('Key set with success')

            case '2':
                try:
                    plaintext = bytes.fromhex(input('Plaintext (hex): '))
                except ValueError:
                    print('Provide an hexadecimal string!')
                    continue

                if(len(plaintext) % DES.block_size != 0):
                    print(f'Plaintext is not aligned with the block size of {DES.block_size} bytes')
                    continue

                cipher_5DES.encrypt(plaintext)
                print('Encryption succeded')

            case '3':
                cipher_5DES.encrypt_flag()
                print('Flag encryption succeded')

            case '4':
                cipher_5DES.encrypt_last_operation_output()
                print('Last operation output encryption succeded')

            case '5':
                # you can only decrypt already encrypted data
                if(not cipher_5DES.decrypt()):
                    print('Can\'t decrypt this :(')
                    continue
                print('Decryption succeded')

            case '6':
                print('You almost got me...')
                continue

            case '7':
                if(FLAG.encode() == cipher_5DES.last_operation_output):
                    print(f'Congrats, this is your flag: {FLAG}')
                    break
                else:
                    print('Try again, I know you can do it ;)')

            case _:
                print('Goodbye :)')
                break


if __name__=='__main__':
    main()