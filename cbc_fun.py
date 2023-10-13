#!/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

key = b'K' * 32
iv = b'my iv'.ljust(16)

cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
plaintexts = [b'block 0'.ljust(AES.block_size),
              b'block 1'.ljust(AES.block_size)]
ciphertext = cipher.encrypt(plaintexts[0] + plaintexts[1])

blocks = [ciphertext[0:16], ciphertext[16:32]]


def decrypt(msg, key=key, iv=iv):
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    return cipher.decrypt(msg)


print(decrypt(blocks[0] + blocks[1]))
print(decrypt(blocks[1], iv=blocks[0]))

# evils
new_text = b'hi'.ljust(16)
diff = strxor(blocks[0], strxor(plaintexts[1], new_text))
print(decrypt(blocks[1], iv=diff))
