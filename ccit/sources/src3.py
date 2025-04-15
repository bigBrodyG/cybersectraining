#!/usr/local/bin/python

import os
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

FLAG = os.getenv("FLAG")
available_songs = [
                    'Zeddy Will - Cha Cha',
                    'Josean Log - Chachacha',
                    'Mr C The Slide Man - Cha-Cha Slide',
                    'Jessica Jay - Chilly Cha Cha',
                    'Kaarija - Cha Cha Cha'
                  ]
secret_song = 'Freddie Dredd - Cha Cha'


def banner():
    print()
    print('Select a song from the list below, I will give you a ticket to play it')
    for i,song_name in enumerate(available_songs):
        print(f'{i}. {song_name}')
    print(f'{i+1}. Play song')
    print(f'{i+2}. Exit')


def main():
    key = get_random_bytes(32)

    print('Welcome to the crypto dance floor, have fun!')
    while(True):
        banner()

        try:
            choice = int(input('> '))
        except ValueError:
            print('Invalid option')
            continue

        if(choice < 0):
            print('Negative numbers are not allowed!')
            continue

        elif(choice < len(available_songs)):
            cipher = ChaCha20.new(key=key)
            ct = cipher.encrypt(available_songs[choice].encode())
            ticket = cipher.nonce.hex() + ct.hex()
            print(f'This is your ticket: {ticket}')

        elif(choice == len(available_songs)):
            ticket = input('Ticket (hex): ')
            try:
                ticket = bytes.fromhex(ticket)
            except ValueError:
                print('Provide an hexadecimal string!')
                continue

            if(len(ticket) < 8):
                print('Provide a ticket of at least 8 bytes!')
                continue

            nonce = ticket[:8]
            ct = ticket[8:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            song_name = cipher.decrypt(ct)

            try:
                song_name = song_name.decode('ascii')
            except UnicodeDecodeError:
                print('Something has gone terribly wrong!')
                continue

            if(song_name in available_songs):
                print(f'"{song_name}" is a very good one, it makes me wanna dance')
            elif(song_name == secret_song):
                print('I don\'t know how you managed to play this song, but')
                print('it\'s so good I want to reward you.')
                print(f'Take this flag: {FLAG}')
                break
            else:
                print('You are doing something suspicious, aren\'t you?')

        elif(choice == len(available_songs)+1):
            print('Goodbye')
            break


if __name__=='__main__':
    main()