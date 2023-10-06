#!/usr/bin/env python3

from Cryptodome.Cipher import AES

BLOCK_SIZE = AES.block_size
KEY_SIZE = 32
iv = b"Some IV".ljust(BLOCK_SIZE)
key = b"My secret key".ljust(KEY_SIZE)

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = b"My super dupa secret message, which none will ever know!"


def pad_msg(msg):
    ''' PKCS5 padding '''
    nb_padding_bytes = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = nb_padding_bytes.to_bytes(1, 'big')
    return msg.ljust(len(msg) + nb_padding_bytes, padding)


# Encrypt it, prepend the IV
ciphertext = iv + cipher.encrypt(pad_msg(plaintext))


def oracle(content):
    '''
    Our oracle, decrypts and then verifies the padding
    '''
    cipher = AES.new(key, AES.MODE_CBC, iv)
    res = cipher.decrypt(bytes(content))
    p = res[-1:]
    return res[-ord(p):] == p * ord(p)


def find_padding_size(ciphertext):
    """
    Flip bits in the ciphertext until we get a padding error from our oracle
    """
    ciphertext = list(ciphertext)

    p = BLOCK_SIZE
    ciphertext[-BLOCK_SIZE - p] ^= 1
    while oracle(ciphertext):
        p -= 1
        ciphertext[-BLOCK_SIZE - p] ^= 1
    return p


padding_size = find_padding_size(ciphertext)
print(f"Padding size appears to be {padding_size}")


def reverse_last_block(padding_size, ciphertext):
    """
    Reverses the last block of the message.
    This increases the padding size in the message,
    byte for byte until the entire block is padding.
    """
    content = list(ciphertext)
    dec_size = len(ciphertext) - BLOCK_SIZE
    
    # We already know the padding size, we could calculate the xor key
    # for those bytes
    # for p in range(1, padding_size + 1):
    #     dec_key[-p] = msg[-p - BLOCK_SIZE] ^ padding_size
    
    for p in range(padding_size + 1, BLOCK_SIZE + 1):
        i = dec_size - p
        for j in range(1, p):
            # flip the bits between the old value and the new value
            content[dec_size - j] ^= (p - 1) ^ p

        # brute-force the new padding byte
        for k in range(256):
            content[i] = k
            if oracle(content):
                # Padding accepted, found a new byte
                # Calculate the 'decryption key'
                dec_key = k ^ p
                
                # Decrypt the byte
                decrypted_msg[i] = dec_key ^ ciphertext[i]
                break
        else:
            raise Exception(f"Failed to reverse byte {i}")


def reverse_block(ciphertext, b):
    """
    Reverses the block number b of the message.
    Almost the same, this time leave out the last block(s)
    Brute force the last byte so it has a valid padding value of 1
    then continue decrypting the rest of the block
    """
    assert 2 <= b < nb_blocks

    content = list(ciphertext[: b * BLOCK_SIZE])
    for p in range(1, BLOCK_SIZE + 1):
        i = (b - 1) * BLOCK_SIZE - p
        for j in range(1, p):
            content[(b - 1) * BLOCK_SIZE - j] ^= (p - 1) ^ p

        for k in range(256):
            content[i] = k
            if oracle(content):
                dec_key = k ^ p
                decrypted_msg[i] = dec_key ^ ciphertext[i]
                break
        else:
            raise Exception(f"Failed to reverse byte {i}")


decrypted_msg = [b'?'] * (len(ciphertext) - BLOCK_SIZE - padding_size)

reverse_last_block(padding_size, ciphertext)

# Now handle the remaining blocks
nb_blocks = len(ciphertext) // BLOCK_SIZE
for b in range(nb_blocks - 1, 1, -1):
    reverse_block(ciphertext, b)

print("Decrypted message:")
print(bytes(decrypted_msg))
assert bytes(decrypted_msg) == plaintext
