# QUICK-DH-AES-CLI

This simple CLI app allows you to do Diffie-Hellman key exchange with someone over an unsecure channel, then, this app makes it simple to encrypt text and decrypt ciphers via AES - 
the latter of which you can send over said unsecure channel.

This app also provides an automatic HMAC of the message, mixed with the derived sercet from the initial DH key exchange, to check for tampering
and message intergrity.

This app does not provide identity verification, it is assumed that both users have a method to identify each other beforehand.

## DISCLAIMER

This was designed as a fun project for me and my buddies, don't use this for anything important.
