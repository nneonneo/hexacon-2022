from encrypt import LEA, bytes_to_words, words_to_bytes, rotate_left, rotate_right
from Crypto.Util.Padding import unpad

def _decrypt_block(self, block):
    state = bytes_to_words(block)
    for i in reversed(range(24)):
        old_state = [state[3]]
        old_state.append(rotate_right(state[0], 9) ^ old_state[0] ^ self.round_keys[i][0] ^ self.round_keys[i][1])
        old_state.append(rotate_left(state[1], 5) ^ old_state[1] ^ self.round_keys[i][2] ^ self.round_keys[i][3])
        old_state.append(rotate_left(state[2], 3) ^ old_state[2] ^ self.round_keys[i][4] ^ self.round_keys[i][5])
        state = old_state
    return words_to_bytes(state)

def decrypt(self, ciphertext):
    assert len(ciphertext) % 16 == 0

    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        plaintext += _decrypt_block(self, ciphertext[i:i+16])
    return unpad(plaintext, 16)

key = bytes.fromhex('a55ae4444740007957c8d24aaf659cf4')

print(decrypt(LEA(key), open("../../chall/level5/test.py.enc", "rb").read()))
print(decrypt(LEA(key), open("../../chall/level5/0day.py.enc", "rb").read()))
