Length extension attack
=======================
*Length extension attack is a type of attack where an attacker can use Hash(message1) and the length of message1 to calculate Hash(message1 ‖ message2) for an attacker-controlled message*  
-- from wikipedia

So.. something like `SHA2(my_secret|data)` where the secret is only know by a real client and server.  
Can be misused by an attacker which does not know the secret, but can effectively construct something like  
`SHA2(my_secret|data|extra_data)`.

The problem
-----------
Certain hash functions, like SHA2, hash a message by splitting the message into multiple blocks.
The last block is always padded up to the block size (64 for SHA2). 
So when hashing `HI`, a block of 64 bytes is hashed (when hashing 64 bytes, actually 128 bytes are hashed).  
In this example SHA2 pads our message something like this:  
`HI | 0x80' | \x00' * padlength (53 bytes) | length (2, encoded as 8 bytes)`.

However SHA does not prevent resuming a hash operation.
So an attacker can take the hash output, feed it in SHA2 (as in reconstruct the internal state)
and can then hash more bytes.

However.. we do need to feed the receiver with different input, because of the padding.  
So to fool the server we must do something like this.  
client calculates: `hash = SHA2(secret | data)` and sends `hash` with the `data` to the server  
attacker calculates: `new hash = SHA2_extend(hash, extra data)` and sends `new hash` with the `data | padding | extra data` to the server

The demo code speaks for itself I suppose.

Examples of 'vulnerable' hash algorithms: SHA1/SHA2/MD5.  
SHA3 or HMAC-SHAx is not vulnerable for these kind of attacks.  
Truncated versions of SHA-2 like SHA-384 are also OK as an attacker does not have all context available to 'resume' the hash operation.
