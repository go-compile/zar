# ZAR (Encrypted Archive Format)

ZAR is encrypted file archive format using modern cryptography and compression.
Utilising [AES 256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [SipHash](https://en.wikipedia.org/wiki/SipHash), [Argon2](https://en.wikipedia.org/wiki/Argon2), [HKDF](https://en.wikipedia.org/wiki/HKDF), [SHA512/SHA256](https://en.wikipedia.org/wiki/SHA-2), [Brotil](https://en.wikipedia.org/wiki/Brotli).

Built to maximise security and compression ratio, all the while being streamable and fast. Utilising AES_256_CTR + SipHash to encrypt and authenticate the archive without requiring the whole file being extracted/read.

## Archive Format

```
Headers
```

```
Encrypted Body
    - []CompressedBlock
        - []FileContents
        - SipHash
    - Almanac/index
```

```
Almanac Offset
```

### Compression Block

Compression block is a collection of file contents and a MAC. A compression block is used to improve compression ratios for small files by combining them together into a bigger block. Compression block size varies and can get quite large depending on what files it contains.

### The Almanac/Index

The almanac is a array of file metadata. Name/path, modified date, size, block offset.
All this information can be used to locate the; first cipher text block, compression block offset form start of cipher block, offset from start of compression block to file & file length.

The almanac is separate from file contents which allows it to be read quickly and not require the full ciphertext from being decrypted. This section is authenticated with SipHash and the "master mac", _the mac used on the full ciphertext_.
