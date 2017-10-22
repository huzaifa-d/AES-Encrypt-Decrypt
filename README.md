# AES Encryption Decryption

This is an implementation of an AES encryption and decryption module using the libcrypt library.
SHA-512 is used as the default hashing function.

## Encryption:
The 'encrypt' program takes an input file and encrypts it using AES128 in Cipher Block Chaining (CBC) Mode.
It prompts the user for a password and uses PBKDF2 (Password Based Key Derivation Function 2) with 4096 iterations (SHA-512).
The encrypted file can be either stored locally (-l option) or transfered by specifying the IP address/port (-d option).
It also appends an HMAC to the encrypted file to enforce non-repudiation.
The 'encrypt' program can also be used to just generate the SHA-512 of the input file (-h option).

## Decryption:
The 'decrypt' program removes the HMAC and throws an erorr if it is not correct.
It then asks for a password, and proceeds to decrypt the encoded file.
It can also run as a network daemon (-d), awaiting incoming network connections on the command-line specified network port.
When a connection comes in, it writes the file data to a temporary file and decodes it. 
It can also run in local mode (-l) in which it bypasses the network functionality and simply decrypts a file specified as input.

Both files will display an error if the output file already exists.

### Usage :
```
encrypt <input file> [-d < IP-addr:port >][-l][-h]
decrypt <filename>  [-d < port >][-l] 
```	    


