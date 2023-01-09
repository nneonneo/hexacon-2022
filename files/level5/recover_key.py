from gf2 import solve_gf2, transpose
from encrypt import LEA
import os

def bytes2bits(by):
    out = []
    for b in by:
        out += [(b >> i) & 1 for i in range(8)]
    return out

plaintext = open("../../chall/level5/test.py.raw~", "rb").read()
ciphertext = open("../../chall/level5/test.py.enc", "rb").read()

inputs = []
outputs = []
for i in range(256):
    key = bytearray(os.urandom(16))
    inputs.append(key)
    output = LEA(key).encrypt(plaintext)
    outputs.append(output)

def xorstr(x, y):
    return bytes(cx ^ cy for cx, cy in zip(x, y))

A = transpose([bytes2bits(c) for c in outputs])
b = bytes2bits(ciphertext)
print(len(A), len(A[0]), len(b))

for x in solve_gf2(A, b):
    if sum(x) % 2 == 1:
        # there are constants involved (delta), so only odd-parity solutions will be valid
        break
else:
    raise Exception("no solution!")

out = b'\0' * len(inputs[0])
for i, v in enumerate(x):
    if v:
        out = xorstr(out, inputs[i])

print(out.hex())
assert LEA(out).encrypt(plaintext) == ciphertext

# This non-deterministically produces one of the working keys.
# There are at least 4 possible keys:
# 0ff04eeeedeaaad3029d871ffa30c9a1
# 5aa51bbbb8bfff86a8372db5509a630b
# a55ae4444740007957c8d24aaf659cf4
# f00fb1111215552cfd6278e005cf365e
