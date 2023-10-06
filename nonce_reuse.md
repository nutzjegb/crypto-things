Nonce-reuse on CTR mode encryption
==================================
Quick recap on how Counter CTR mode encryption works.  
![Counter (CTR) mode](/images/CTR_encryption_2.png)

So ciphertext = `plaintext ^ f(key, nonce)`  
As the output of the function is the same for multiple streams, we know that:  
`ciphertext1 ^ f() = plaintext1`  
`ciphertext2 ^ f() = plaintext2`  

So if we know/guess the plaintext we could calculate the actual key use to encrypt each block (the output of f()).  
(observe that: `plaintext1 ^ plaintext2 = ciphertext1 ^ chipertext2` in this case)

K.. so know what.. I want the plaintext!
----------------------------------------
An attacker can use the same attacks as on a OTP (one-time pad) which has been used more than once.  
Crib dragging is one method to break it, this attacks comes down to guessing common words in plaintext's.  
So we guess plaintext1 start with `FORT`, we test this by calculating  
`plaintext2 = ciphertext2 ^ ('FORT' ^ ciphertext1)`.   
If the first bytes of the plaintext look good, we probably found the correct key.

The example python code uses a more statical approach...

Notes
-----
If you can control the plaintext (chosen plaintext attack) all is lost, as you can simply calculate  
`streamkey = ciphertext ^ plaintext`  
and you can use to found key to decrypt all other messages.

Note to self, when your plaintext is unpredictable (like a truly random key), such an attack is not possible I guess.
