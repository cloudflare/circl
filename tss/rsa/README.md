# RSA Threshold Signatures and Decryption

This is an implementation of ["Practical Threshold Signatures" by Victor Shoup](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf).
Protocol 1 is implemented.

## Threshold Primer

Let *l* be the total number of players, *t* be the number of corrupted players, and *k* be the threshold.
The idea of threshold signatures is that at least *k* players need to participate to form a valid signature.

Setup consists of a dealer generating *l* key shares from a key pair and "dealing" them to the players. In this implementation the dealer is trusted.

During the signing phase, at least *k* players use their key share and the message to generate a signature share.
Finally, the *k* signature shares are combined to form a valid signature for the message.

## Threshold RSA-OAEP decryption

Use an RSA key pair dedicated to encryption, with a modulus of at least 2048 bits and a threshold of at least two. `GenerateKey` uses safe primes as in Shoup's analysis of threshold signatures. A trusted dealer calls `Deal` as for signatures, using the encryption key. Each player calls `NewOAEPDecrypter` during trusted setup with its share and the corresponding public key from trusted provisioning. An attacker-controlled modulus can disclose the player's long-term key share. The constructor validates and encodes the secret share using variable-time `math/big` operations. Complete setup before serving requests and reuse the resulting decrypter, which uses fixed-width secret exponents during requests.

Senders use ordinary `crypto/rsa.EncryptOAEP` with SHA-256. Each selected participant calls `DecryptShare` on the same ciphertext. The recipient obtains contributions over protected and authenticated channels, and calls `CombineDecryptionSharesOAEP` with the trusted public key, the original player count, threshold, ciphertext, and OAEP label. The combiner validates the aggregate RSA result and decodes OAEP into plaintext. A full private key is only needed during dealing.

Each ciphertext must have the same byte length as the modulus, represent an integer less than the modulus, and be coprime to it. Threshold interpolation needs the ciphertext's modular inverse. A ciphertext with no inverse returns `rsa.ErrDecryption`, even if a conventional RSA-OAEP implementation could decrypt it.

Treat access to `DecryptShare` as access to that player's RSA private operation. Authorize requests at each participant and send the contributions only to a trusted, authenticated combiner. The contributions are available before OAEP validation and are algebraically malleable. Application security analysis must account for parties who can request or obtain contributions, including in the presence of colluding participants. Use a separate key pair for signing, since the two schemes share the underlying RSA private operation.

A player producing an invalid share can cause a combination to fail. Select a different subset if enough players remain. Use a trusted, deployment-sized participant count. The operation cost grows with the bit length of the factorial of the total participant count, even when only a subset contributes. See [RFC 8017, Section 7.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1) for OAEP.

## Modifications

1. Our implementation is not robust. That is, the corrupted players can prevent a valid signature from being formed by the non-corrupted players. As such, we remove all verification.
2. The paper requires p and q to be safe primes. `GenerateKey` uses safe primes, while `Deal` accepts externally generated keys without checking this property.
