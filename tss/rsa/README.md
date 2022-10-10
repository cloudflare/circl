# RSA Threshold Signatures

This is an implementation of ["Practical Threshold Signatures" by Victor Shoup](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf).
Protocol 1 is implemented.

## Threshold Primer

Let *l* be the total number of players, *t* be the number of corrupted players, and *k* be the threshold.
The idea of threshold signatures is that at least *k* players need to participate to form a valid signature.

Setup consists of a dealer generating *l* key shares from a key pair and "dealing" them to the players. In this implementation the dealer is trusted.

During the signing phase, at least *k* players use their key share and the message to generate a signature share.
Finally, the *k* signature shares are combined to form a valid signature for the message.

## Modifications

1. Our implementation is not robust. That is, the corrupted players can prevent a valid signature from being formed by the non-corrupted players. As such, we remove all verification.
2. The paper requires p and q to be safe primes. We do not.