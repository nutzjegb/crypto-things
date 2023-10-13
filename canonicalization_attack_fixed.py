#!/bin/env python3
# Note that this 'fix' is only to demonstrates a PAE function.
# There is more stuff that needs te fixed.

import struct
from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256, HMAC


def derive_key(key):
    return (HMAC.new(key, b'enc', digestmod=SHA256).digest(),
            HMAC.new(key, b'auth', digestmod=SHA256).digest())


def pae(arr):
    '''
    Encode a message using the
    PASETO (platform-agnostic security tokens)
    PAE (Pre-Authentication Encoding) standard
    '''
    def LE64(length):
        assert length < 1 << 64
        return struct.pack('<Q', length)

    output = LE64(len(arr))
    for el in arr:
        output += LE64(len(el))
        output += el

    return output


def encrypt_with_context(key, nonce, plaintext, aad):
    enc_key, auth_key = derive_key(key)

    cipher = AES.new(enc_key, nonce=nonce, mode=AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)

    hmac = HMAC.new(auth_key, digestmod=SHA256)
    hmac.update(pae([nonce, ciphertext, aad]))
    mac = hmac.digest()

    return {"nonce": nonce, "ciphertext": ciphertext, "aad": aad, "mac": mac}


def server_rotate_key(nonce, ciphertext, aad, mac):
    # First we verify, at we should always verify stuff before using it
    secret_key = b'K' * 32
    enc_key, auth_key = derive_key(secret_key)
    hmac = HMAC.new(auth_key, digestmod=SHA256)
    hmac.update(pae([nonce, ciphertext, aad]))
    if hmac.digest() != mac:
        raise Exception('Server: Not buying it.. signature is not valid')

    # Now decrypt our new key
    cipher = AES.new(enc_key, nonce=nonce, mode=AES.MODE_CTR)
    # In counter mode, encrypt/decrypt is the same
    new_key = cipher.encrypt(ciphertext)
    print(f"Server: rotating key to: {hexlify(new_key)}")
    print(f"Server: metadata: {aad}")


my_key = b'K' * 32
nonce = get_random_bytes(15)
r1 = encrypt_with_context(my_key, nonce, b'My new key'.ljust(32, b'y'),
                          b'good day to rotate a key')
server_rotate_key(**r1)

# Evils?
try:
    print("Commence evils")
    server_rotate_key(r1["nonce"], b'',
                      r1["ciphertext"] + r1["aad"], r1["mac"])
except Exception as e:
    # print but ignore the error
    print(e)
else:
    raise Exception('Server should have rejected the cmd')

# Observer the MAC is different now
r2 = encrypt_with_context(my_key, nonce, b'', r1["ciphertext"] + r1["aad"])

assert r1["mac"] != r2["mac"]
print(f'MAC:\n {hexlify(r1["mac"])} !=\n {hexlify(r2["mac"])}')
