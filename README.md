# CIRCL
[![CircleCI](https://circleci.com/gh/cloudflare/circl/tree/master.svg?style=svg&circle-token=a184a4d0cbff045907c8061bda35fc17dab465dc)](https://circleci.com/gh/cloudflare/circl/tree/master)

CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection of cryptographic primitives written in Go. This library includes a set of packages that target cryptographic algorithms for post-quantum (PQ) elliptic curve cryptography, and pairing algorithms. Goal of the project is for library to be used as an effective tool for deploying secure cryptography providing high quality, clear, performant, and secure code. 

## Implemented primitives

| Cathegory | Algorithms | Description | Applications |
|-----------|------------|-------------|--------------|
| Post-quantum cryptography | SIDH, SIKE | Isogeny-based cryptography. SIDH provide key exchange mechanisms using ephemeral keys. SIKE is a key encapsulation method (KEM). | Experiments with TLS |
| Key Exchange | X25519, X448 | RFC-7748 provides new key exchange mechanisms based on Montgomery elliptic curves. | TLS 1.3. Secure Shell. |
| Key Exchange | FourQ | One of the fastest elliptic curves at 128-bit security level. | Experimental for key agreement and digital signatures. | 
| Key Exchange | P-384 | Our optimizations reduce the burden when moving from P-256 to P-384. |  ECDSA and ECDH using Suite B at top secret level. |


### Installation

You can get it by typing:

```
go get github.com/cloudflare/circl
```

###  Testing and Benchmarking

Library comes with number of make targets which can be used for testing and benchmarking:

* ``test``: performs testing of the binary
* ``bench``: runs benchmarks
* ``cover``: produces coverage

### Contributing

To contribute, fork this repo and make your changes. Then, make a PR to this repo. A PR requires at least one approval from a repo admin and successful CI build.

### Security

This library is offered as-is, and without a guarantee. Therefore, we recommend that you take caution before using it in a production application.

### License

The project is licensed under the BSD License.