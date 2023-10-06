#!/bin/env python3

from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

key = b'K' * 32
iv = b'my iv'.ljust(16)

cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
plaintexts = [b'block 0'.ljust(AES.block_size),
              b'8'.ljust(AES.block_size, b'8')]
ciphertext = cipher.encrypt(plaintexts[0] + plaintexts[1])

print(len(ciphertext))
blocks = [ciphertext[0:16], ciphertext[16:32]]

bkey0 = strxor(blocks[0], plaintexts[0])
bkey1 = strxor(blocks[1], plaintexts[1])

print(f"test: {strxor(blocks[0], bkey0)}")
print(f"test: {strxor(blocks[1], bkey1)}")

cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
print(cipher.decrypt(blocks[0] + blocks[1]))

cipher = AES.new(key, mode=AES.MODE_CBC, iv=blocks[0])
print(cipher.decrypt(blocks[1]))


# test
# p = 8 in cipher, p = 9
# ciphertext[i] ^= (p - 1) ^ p
new_text = b'9'.ljust(16, b'9')
diff = strxor(blocks[1], strxor(plaintexts[1], new_text))

cipher = AES.new(key, mode=AES.MODE_CBC, iv=blocks[0])
print(cipher.decrypt(diff))
# shit..
