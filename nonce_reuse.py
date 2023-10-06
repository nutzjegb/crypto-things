#!/bin/env python3

from binascii import hexlify
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

key = b'K' * 32
nonce = b'my nonce'

strings = (
    b'hi everybody, here is a full block of secret messages.       ',
    b'lorem ipsum dolor sit amet, consectetur adipiscing elit. done',
    b'velit ante, euismod fermentum fringilla in, ullamcorper in mi',
    b'donec et aliquet sapien, sit amet laoreet mi. fusce tempus, q',
    b'dapibus fermentum vehicula, sem elit lobortis est, blandit fa',
    b'ilisis enim mauris a ex. nulla vel volutpat orci. donec in ni',
    b'si euismod, euismod ante sed, porta ex. suspendisse feugiat, ',
    b'ros eget vehicula volutpat, nulla diam pharetra arcu, eget ru',
    b'um tellus diam eget eros. etiam pellentesque fringilla dolor,',

    # Comment this block, to demonstrate we do need a a good amount of data
    # to reconstruct our messages
    b'in pulvinar lorem feugiat vitae. nunc sagittis dolor eget urn',
    b'bibendum consequat. nullam tincidunt ut turpis at ornare. sed',
    b'pellentesque ac mi eu imperdiet. sed nec massa ut nibh suscip',
    b'it suscipit. donec finibus tristique tincidunt. morbi ut effi',
    b'itur diam, sit amet tempus ex. donec posuere mollis justo, si',
    b'en einde van het voorbeeld, nu maar kijken of dit gaat werken',
    b'curabitur ut tincidunt est, ultricies euismod elit. proin sag',
    b'ittis facilisis luctus. fusce luctus elementum diam, nec tris',
    b'tique augue blandit lobortis. vivamus facilisis magna in nibh',
    b'ullamcorper, at consequat nunc ultricies. pellentesque varius',
    b'mi est, ut faucibus ante pharetra vel. morbi condimentum feli',
    b's feugiat sodales feugiat. integer vitae varius purus. maecen',
    b'as eros massa, ornare ac ultrices ac, finibus id nisi. proin ',
    b'rutrum quam. morbi aliquam at elit eu mattis. nullam id ipsum',
    b' vel metus tristique ullamcorper non sed ante. nunc feugiat l',
    b'acus id enim placerat, in dignissim orci viverra. proin erat ',
    b'nibh, finibus vel finibus vel, vulputate et ante. proin ultri',
    b'cies varius nulla, non condimentum ante ultrices vitae. quisq',

    b'and this is our last secret message. isnt crypto fun. bye bye',
)

# Encrypt all our strings
ciphertexts = []
for string in strings:
    cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
    ciphertexts.append(cipher.encrypt(string))

# To verify our found key later on
actual_key = strxor(strings[0], ciphertexts[0])


def find_key(ciphertext):
    '''
    this is sort of a crib-dragging method
    to find the best key for our ciphertext.
    We do not try to find words though, only a small set of ascii bytes.
    '''

    # a-z + ' ,.'
    ascii_text_chars = list(range(97, 123)) + [32, 44, 46]

    best = 0
    found_key_byte = b''
    for i in range(256):
        possible_key = i.to_bytes(1, 'big')
        keystream = possible_key * len(ciphertext)

        # Xor our ciphertext with or key
        candidate_message = strxor(ciphertext, keystream)
        # Count the number of found ascii chars
        nb_letters = sum([x in ascii_text_chars for x in candidate_message])

        # Keep the best one
        if nb_letters > best:
            best = nb_letters
            found_key_byte = possible_key
    return found_key_byte


# Create a 'column' of our ciphertexts
# So strings ['abc', 'def', 'ghi'] becomes ['adg', 'beh, 'cfi']
columns = list(zip(*ciphertexts))
found_key = b''
for c in columns:
    found_key += find_key(bytes(c))
print(f"found key: {hexlify(found_key)}")

print(strxor(found_key, ciphertexts[0]))
print(strxor(found_key, ciphertexts[-1]))
assert actual_key == found_key
