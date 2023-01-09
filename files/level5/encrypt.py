# uncompyle6 version 3.8.0
# Python bytecode 3.7.0 (3394)
# Decompiled from: Python 3.7.9 (v3.7.9:13c94747c7, Aug 15 2020, 01:31:08) 
# [Clang 6.0 (clang-600.0.57)]
# Embedded file name: encrypt.py
from datetime import date
from glob import glob
from os import remove

def bytes_to_words(b):
    return [int.from_bytes(b[i:i + 4], 'little') for i in range(0, len(b), 4)]


def words_to_bytes(w):
    return (b'').join([i.to_bytes(4, 'little') for i in w])


def rotate_left(x, n):
    return x << n & 4294967295 | x >> 32 - n & 4294967295


def rotate_right(x, n):
    return x << 32 - n & 4294967295 | x >> n & 4294967295


def pad(b):
    padding = 16 - len(b) % 16
    return b + padding * bytes([padding])


class LEA:

    def __init__(self, key):
        # real LEA deltas
        self.deltas = (3287280091, 1147300610, 2044886154, 2027892972, 1902027934,
                       3347438090, 3763270186, 3854829911)
        self.round_keys = self._key_schedule(key)

    def _key_schedule(self, key):
        round_keys = []
        state = bytes_to_words(key)
        for i in range(24):
            state[0] = rotate_left(state[0] ^ rotate_left(self.deltas[(i % 4)], i), 1)
            state[1] = rotate_left(state[1] ^ rotate_left(self.deltas[(i % 4)], i + 1), 3)
            state[2] = rotate_left(state[2] ^ rotate_left(self.deltas[(i % 4)], i + 2), 6)
            state[3] = rotate_left(state[3] ^ rotate_left(self.deltas[(i % 4)], i + 3), 11)
            round_keys.append((state[0], state[1], state[2], state[1], state[3], state[1]))

        return round_keys

    def _encrypt_block(self, block):
        state = bytes_to_words(block)
        for i in range(24):
            old_state = state[:]
            state[0] = rotate_left(old_state[0] ^ self.round_keys[i][0] ^ old_state[1] ^ self.round_keys[i][1], 9)
            state[1] = rotate_right(old_state[1] ^ self.round_keys[i][2] ^ old_state[2] ^ self.round_keys[i][3], 5)
            state[2] = rotate_right(old_state[2] ^ self.round_keys[i][4] ^ old_state[3] ^ self.round_keys[i][5], 3)
            state[3] = old_state[0]

        return words_to_bytes(state)

    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self._encrypt_block(plaintext[i:i + 16])

        return ciphertext


if __name__ == '__main__':
    if date.today() > date.fromisoformat('2022-04-01'):
        try:
            remove('C:\\key.txt')
        except:
            pass

    with open('C:\\key.txt', 'rb') as (f):
        key = f.read()
    lea = LEA(key)
    for path in glob('C:\\exploits\\*.raw'):
        with open(path, 'rb') as (f):
            content = f.read()
        enc = lea.encrypt(content)
        with open(path[:-3] + 'enc', 'wb') as (f):
            f.write(enc)
        remove(path)