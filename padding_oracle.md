Padding oracle attack on CBC encryption
=======================================
As CBC requires a full-block to encrypt, input data needs to be padded before it can be encrypted.
There are a lot of padding standards, a popular one is PKCS#5, which appends N padding bytes of value N.
So when a message contains 4 bytes of padding, the last bytes of the block would contain 4 bytes with the value 0x04.  
`| unknown plaintext byte | .. | 0x04 | 0x04 | 0x04 | 0x04 |`

When a message processed, it is decrypted, the last byte would be checked (as it contains the number of padding bytes),
the padding is checked and removed from the plaintext. If the padding is incorrect the server returns a error.
The problem here is that an attacker can detect, either through a special error (eg server 500) or due timing,
when there is a padding error or a decryption error.

Quick recap on how Cipher block chaining (CBC) mode works.  
![Cipher block chaining (CBC) encryption](/images/CBC_encryption.png)
![Cipher block chaining (CBC) decryption](/images/CBC_decryption.png)

Notice that when decryption, changing a bit in the second to last ciphertext block, will alter the output of the last block.

So a possible attack is to modify bytes in the last block to learn the size of the padding.
So start at the first byte of the last block, flip a bit, see if the server returns a padding error.
If not, flip a bit in the next byte, until you get a padding error.
For example: after flipping a bit in byte 11 (of the last block), and the receiver returns a padding error, then we know the last 4 bytes of the plaintext equal 0x04.

Now that we know the value, we can change the last bytes from 0x04 to 0x05 by modifying the second to last ciphertext block as such:  
`block[-2][12..15] ^= block[-1][12..15] ^ (0x04 ^ 0x05)`

Now we only need to brute force 1 byte in the ciphertext to get a valid padding (as we only modified the the last four bytes from 0x04 to 0x05). So now modify the next byte in the second to last block so it would decrypt to 0x05, so in this example we change the value at byte position 11 in the second to last block until we no longer get a padding error.
This will learns us the xor key of byte 11. We continue this attack until we learn the entire xor key of the last block.
Now we remove the last block from the ciphertext and repeat the attack on the remaining blocks (see the code example).