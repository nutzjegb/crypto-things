#!/bin/env python3

from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256, HMAC


def derive_key(key):
    return (HMAC.new(key, b'enc', digestmod=SHA256).digest(),
            HMAC.new(key, b'auth', digestmod=SHA256).digest())


def encrypt_with_context(key, nonce, plaintext, aad):
    enc_key, auth_key = derive_key(key)

    cipher = AES.new(enc_key, nonce=nonce, mode=AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)

    hmac = HMAC.new(auth_key, digestmod=SHA256)
    hmac.update(nonce)
    hmac.update(ciphertext)
    hmac.update(aad)
    mac = hmac.digest()

    return {"nonce": nonce, "ciphertext": ciphertext, "aad": aad, "mac": mac}


def server_rotate_key(nonce, ciphertext, aad, mac):
    # First we verify, at we should always verify stuff before using it
    secret_key = b'K' * 32
    enc_key, auth_key = derive_key(secret_key)
    hmac = HMAC.new(auth_key, digestmod=SHA256)
    hmac.update(nonce + ciphertext + aad)
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

# Evils below













input('Hit a key for evils..')
# See if we can fool the server
print("Commence evils")
server_rotate_key(r1["nonce"], b'', r1["ciphertext"] + r1["aad"], r1["mac"])

# Note that this is the basically the same as above,
# observe our 'input collision'
r2 = encrypt_with_context(my_key, nonce, b'', r1["ciphertext"] + r1["aad"])

assert r1["mac"] == r2["mac"]
print(f'MAC:\n {hexlify(r1["mac"])} ==\n {hexlify(r2["mac"])}')
