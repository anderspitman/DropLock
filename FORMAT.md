# DropLock format

Request link:

```txt
#k=base64url(raw P-256 public key)
```

Encrypted message link:

```txt
#m=base64url(binary message)
```

The same binary message can be sent as a `.droplock` file.

## Binary message

All offsets are bytes.

| Offset | Size | Field                                         |
| -----: | ---: | --------------------------------------------- |
|      0 |    4 | magic: `DLCK`                                 |
|      4 |    1 | format version: `1`                           |
|      5 |   65 | recipient raw uncompressed P-256 public key   |
|     70 |   65 | ephemeral raw uncompressed P-256 public key   |
|    135 |   12 | AES-GCM nonce                                 |
|    147 | rest | AES-GCM ciphertext and tag                    |

Crypto:

| Item       | Value                                             |
| ---------- | ------------------------------------------------- |
| ECDH       | P-256                                             |
| KDF        | HKDF-SHA-256                                      |
| HKDF salt  | `ephemeral public key || recipient public key`    |
| HKDF info  | `droplock aes-gcm`                                |
| Encryption | AES-256-GCM                                       |
| AAD        | bytes `0..146` of the binary message header       |

## Encrypted plaintext

All offsets are bytes after decryption.

| Offset | Size     | Field                                      |
| -----: | -------: | ------------------------------------------ |
|      0 |        1 | payload type: `1` text, `2` file           |
|      1 |        2 | filename length, uint16 big-endian         |
|      3 |        2 | MIME type length, uint16 big-endian        |
|      5 | variable | UTF-8 filename                             |
|    ... | variable | UTF-8 MIME type                            |
|    ... |     rest | payload bytes; text payloads are UTF-8     |
