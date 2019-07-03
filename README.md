<img src=".etc/icon.png" align="right" height="300" width="300"/>

# CIRCL
[![CircleCI](https://circleci.com/gh/cloudflare/circl/tree/master.svg?style=svg)](https://circleci.com/gh/cloudflare/circl/tree/master)
[![GoDoc](https://godoc.org/github.com/cloudflare/circl?status.svg)](https://godoc.org/github.com/cloudflare/circl)
[![Go Report Card](https://goreportcard.com/badge/github.com/cloudflare/circl)](https://goreportcard.com/report/github.com/cloudflare/circl)

**CIRCL** (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection
of cryptographic primitives written in Go. The goal of this library is to be used as a tool for
experimental deployment of cryptographic algorithms targeting Post-Quantum (PQ) and Elliptic
Curve Cryptography (ECC).


### Security Disclaimer

🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental.


### Installation

You can get it by typing:

```sh
 $ go get -u github.com/cloudflare/circl
```


### Implemented Primitives

| Category | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| PQ Key Exchange | SIDH | SIDH provide key exchange mechanisms using ephemeral keys. | Post-quantum key exchange in TLS |
| PQ KEM | SIKE | SIKE is a key encapsulation mechanism (KEM). | Post-quantum key exchange in TLS |
| Key Exchange | X25519, X448 | RFC-7748 provides new key exchange mechanisms based on Montgomery elliptic curves. | TLS 1.3. Secure Shell. |
| Key Exchange | FourQ | One of the fastest elliptic curves at 128-bit security level. | Experimental for key agreement and digital signatures. |
| Key Exchange / Digital signatures | P-384 | Our optimizations reduce the burden when moving from P-256 to P-384. |  ECDSA and ECDH using Suite B at top secret level. |
| Digital Signatures | Ed25519 | RFC-8032 provides new signature schemes based on Edwards curves. | Digital certificates and authentication. |

### Work in Progress

| Category | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| Hashing to Elliptic Curve Groups | Several algorithms: Elligator2, Ristretto, SWU, Icart. | Protocols based on elliptic curves require hash functions that map bit strings to points on an elliptic curve.  | VOPRF. OPAQUE. PAKE. Verifiable random functions. |
| Bilinear Pairings | Plans for moving BN256 to stronger pairing curves. | A bilineal pairing is a mathematical operation that enables the implementation of advanced cryptographic protocols, such as identity-based encryption (IBE), short digital signatures (BLS), and attribute-based encryption (ABE). | Geo Key Manager, Randomness Beacon, Ethereum and other blockchain applications. |
| PQ KEM | HRSS-SXY | Lattice (NTRU) based key encapsulation mechanism. | Key exchange for low-latency environments |
| PQ KEM | Kyber | Lattice (M-LWE) based key encapsulation mechanism. | Post-Quantum Key exchange |
| PQ Key Exchange | cSIDH | Isogeny based drop-in replacement for Diffie–Hellman | Post-Quantum Key exchange. |
| PQ Digital Signatures | SPHINCS+ | Stateless hash-based signature scheme | Post-Quantum PKI |


### Testing and Benchmarking

Library comes with number of make targets which can be used for testing and
benchmarking:

*   ``test``: performs testing of the binary.
*   ``bench``: runs benchmarks.
*   ``cover``: produces coverage.
*   ``lint`` : runs set of linters on the code base.

### Contributing

To contribute, fork this repository and make your changes, and then make a Pull
Request. A Pull Request requires approval of the admin team and a successful
CI build.


### License

The project is licensed under the BSD License.
