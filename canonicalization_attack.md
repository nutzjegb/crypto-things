Canonicalization attack
=======================
*Canonicalization Attacks occur when a protocol that feeds data into a hash function used in a Message Authentication Code (MAC) fails to ensure some property that’s expected of the overall protocol.*

*The textbook example of a canonicalization attack is the length-extension attack against hash functions such as MD5/SHA, which famously broke the security of Flickr’s API signatures.*  
-- Taken from [soatok.blog](https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/)

This example demos a Authenticated encryption with associated data (AEAD) function, build with a CTR+HMAC function.
However some mistakes where made.

Also see [length extension attack](./length_extension_attack.md).
