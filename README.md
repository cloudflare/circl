# CIRCL
[![CircleCI](https://circleci.com/gh/cloudflare/circl/tree/master.svg?style=svg&circle-token=a184a4d0cbff045907c8061bda35fc17dab465dc)](https://circleci.com/gh/cloudflare/circl/tree/master)

CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection
of cryptographic primitives written in Go. This library includes a set of
packages that target cryptographic algorithms for Post-Quantum (PQ), and Elliptic
Curve Cryptography (ECC). The goal of this library is to be used as an effective
tool for deploying secure cryptography providing high quality, clear, high
performance, and secure code.

## Implemented Primitives

| Category | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| Post-Quantum Cryptography | SIDH, SIKE | Isogeny-based cryptography. SIDH provide key exchange mechanisms using ephemeral keys. SIKE is a key encapsulation method (KEM). | Experiments with TLS |
| Key Exchange | X25519, X448 | RFC-7748 provides new key exchange mechanisms based on Montgomery elliptic curves. | TLS 1.3. Secure Shell. |
| Key Exchange | FourQ | One of the fastest elliptic curves at 128-bit security level. | Experimental for key agreement and digital signatures. |
| Key Exchange / Digital signatures | P-384 | Our optimizations reduce the burden when moving from P-256 to P-384. |  ECDSA and ECDH using Suite B at top secret level. |

## Work in Progress

| Category | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| Hashing to Elliptic Curve Groups| Several algorithms: Elligator2, Ristretto, SWU, Icart. | Protocols based on elliptic curves require hash functions that map bit strings to points on an elliptic curve.  | Privacy Pass. OPAQUE. PAKE. Verifiable random functions. |
| Bilinear Pairings | Plans for moving BN256 to stronger pairing curves. | A bilineal pairing is a mathematical operation that enables the implementation of advanced cryptographic protocols, such as identity-based encryption (IBE), short digital signatures (BLS), and attribute-based encryption (ABE). | Geo Key Manager, Randomness Beacon, Ethereum and other blockchain applications. |


### Installation

You can get it by typing:

```sh
 $ go get -u github.com/cloudflare/circl
```

### Testing and Benchmarking

Library comes with number of make targets which can be used for testing and
benchmarking:

*   ``test``: performs testing of the binary
*   ``bench``: runs benchmarks
*   ``cover``: produces coverage

### Contributing

To contribute, fork this repository and make your changes, and then make a Pull
Request. A Pull Request requires approval of the admin team and a successful
CI build.

### Security

This library is offered as-is, and without a guarantee. Therefore, we recommend
that you take caution before using it in a production application.

### License

The project is licensed under the BSD License.
