<img src=".etc/icon.png" align="right" height="300" width="300"/>

# CIRCL

[![GitHub release](https://img.shields.io/github/release/cloudflare/circl.svg)](https://GitHub.com/cloudflare/circl/releases/)
[![CIRCL](https://github.com/cloudflare/circl/workflows/CIRCL/badge.svg)](https://github.com/cloudflare/circl/actions)
[![GoDoc](https://godoc.org/github.com/cloudflare/circl?status.svg)](https://pkg.go.dev/github.com/cloudflare/circl?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/github.com/cloudflare/circl)](https://goreportcard.com/report/github.com/cloudflare/circl)
[![codecov](https://codecov.io/gh/cloudflare/circl/branch/main/graph/badge.svg)](https://codecov.io/gh/cloudflare/circl)

**CIRCL** (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection
of cryptographic primitives written in Go. The goal of this library is to be used as a tool for
experimental deployment of cryptographic algorithms targeting Post-Quantum (PQ) and Elliptic
Curve Cryptography (ECC).

## Security Disclaimer

🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental. All security issues must be reported, please notify us immediately following the instructions given in our [Security Policy](https://github.com/cloudflare/circl/security/policy).

## Installation

You can get CIRCL by fetching:

```sh
go get -u github.com/cloudflare/circl
```

Alternatively, look at the [Cloudflare Go](https://github.com/cloudflare/go/tree/cf) fork to see how to integrate CIRCL natively in Go.

## List of Algorithms

[RFC-7748]: https://doi.org/10.17487/RFC7748
[RFC-8032]: https://doi.org/10.17487/RFC8032
[RFC-8235]: https://doi.org/10.17487/RFC8235
[RFC-9180]: https://doi.org/10.17487/RFC9180
[RFC-9380]: https://doi.org/10.17487/RFC9380
[RFC-9474]: https://doi.org/10.17487/RFC9474
[RFC-9496]: https://doi.org/10.17487/RFC9496
[RFC-9497]: https://doi.org/10.17487/RFC9497
[FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
[FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
[FIPS 186-5]: https://doi.org/10.6028/NIST.FIPS.186-5
[BLS12-381]: https://electriccoin.co/blog/new-snark-curve/
[ia.cr/2015/267]: https://ia.cr/2015/267
[ia.cr/2019/966]: https://ia.cr/2019/966

### Elliptic Curve Cryptography

| Diffie-Hellman Protocol |
|:---:|

- [X25519](./dh/x25519) and [X448](./dh/x448) functions. ([RFC-7748])
- [Curve4Q](./dh/curve4q) function based on FourQ curve. ([draft-ladd-cfrg-4q](https://datatracker.ietf.org/doc/draft-ladd-cfrg-4q/))

| Digital Signature Schemes |
|:---:|

- [Ed25519](./sign/ed25519) and [Ed448](./sign/ed448) signatures. ([RFC-8032])
- [BLS](./sign/bls) signatures. ([draft-irtf-cfrg-bls-signature](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/))

| Prime Groups |
|:---:|

 - [P-256, P-384, P-521](./group). ([FIPS 186-5])
 - [Ristretto](./group) group. ([RFC-9496])
 - [Bilinear pairings](./ecc/bls12381): with the [BLS12-381] curve, and hash to G1 and G2.
 - [Hash to curve](./group), hash to field, XMD and XOF [expanders](./expander). ([RFC-9380])

| High-Level Protocols |
|:---:|

 - [HPKE](./hpke): Hybrid Public-Key Encryption ([RFC-9180])
 - [VOPRF](./oprf): Verifiable Oblivious Pseudorandom functions. ([RFC-9497])
 - [RSA Blind Signatures](./blindsign/blindrsa). ([RFC-9474])
 - [Partially-blind](./blindsign/blindrsa/partiallyblindrsa/) RSA Signatures. ([draft-cfrg-partially-blind-rsa](https://datatracker.ietf.org/doc/draft-amjad-cfrg-partially-blind-rsa/))
 - [CPABE](./abe/cpabe): Ciphertext-Policy Attribute-Based Encryption. ([ia.cr/2019/966])
 - [OT](./ot/simot): Simplest Oblivious Transfer ([ia.cr/2015/267]).
 - [Threshold RSA](./tss/rsa) Signatures ([Shoup Eurocrypt 2000](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf)).
 - [Prio3](./vdaf/prio3) Verifiable Distributed Aggregation Function ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)).

### Post-Quantum Cryptography

| KEM: Key Encapsulation Methods |
|:---:|

 - [ML-KEM](./kem/mlkem): modes 512, 768, 1024 ([FIPS-203](https://doi.org/10.6028/NIST.FIPS.203)).
 - [X-Wing](./kem/xwing) ([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)).
 - [Kyber KEM](./kem/kyber): modes 512, 768, 1024 ([KYBER](https://pq-crystals.org/kyber/)).
 - [FrodoKEM](./kem/frodo): modes 640-SHAKE. ([FrodoKEM](https://frodokem.org/))
 - [CSIDH](./dh/csidh): Post-Quantum Commutative Group Action ([CSIDH](https://csidh.isogeny.org/)).
 - (**insecure, deprecated**) ~~[SIDH/SIKE](./kem/sike)~~: Supersingular Key Encapsulation with primes p434, p503, p751 ([SIKE](https://sike.org/)).

| Digital Signature Schemes |
|:---:|

 - [Dilithium](./sign/dilithium): modes 2, 3, 5 ([Dilithium](https://pq-crystals.org/dilithium/)).
 - [ML-DSA](./sign/mldsa): modes 44, 65, 87 ([FIPS 204]).
 - [SLH-DSA](./sign/slhdsa): twelve parameter sets, pure and pre-hash signing ([FIPS 205]).

### Zero-knowledge Proofs

 - [Schnorr](./zk/dl): Prove knowledge of the Discrete Logarithm. ([RFC-8235])
 - [DLEQ](./zk/dleq): Prove knowledge of the Discrete Logarithm Equality. ([RFC-9497])
 - [DLEQ in Qn](./zk/qndleq): Prove knowledge of the Discrete Logarithm Equality for subgroup of squares in (Z/nZ)\*.

### Symmetric Cryptography

| XOF: eXtendable Output Functions |
|:---:|

 - [SHAKE128 and SHAKE256](./xof) ([FIPS 202]).
 - [BLAKE2X](./xof): BLAKE2XB and BLAKE2XS ([Blake2x](https://www.blake2.net/blake2x.pdf))
 - [KangarooTwelve](./xof/k12): fast hashing based on Keccak-p. ([KangarooTwelve](https://keccak.team/kangarootwelve.html)).
 - SIMD [Keccak](https://keccak.team/keccak_specs_summary.html) f1600 Permutation.

| LWC: Lightweight Cryptography |
|:---:|

- [Ascon v1.2](./cipher/ascon): Family of AEAD block ciphers ([ASCON](https://ascon.iaik.tugraz.at/index.html))

### Misc

| Integers |
|:---:|

- Safe primes generation.
- Integer encoding: wNAF, regular signed digit, mLSBSet representations.

| Finite Fields |
|:---:|

 - Fp25519, Fp448, Fp511, Fp434, Fp503, Fp751.
 - Fp381, and its quadratic, sextic and twelveth extensions.
 - Polynomials in monomial and Lagrange basis.

| Elliptic Curves |
|:---:|

 - P-384 Curve
 - [FourQ](https://eprint.iacr.org/2015/565)
 - [Goldilocks](https://eprint.iacr.org/2015/625)
 - [BLS12-381](https://electriccoin.co/blog/new-snark-curve/)

## Testing and Benchmarking

Library comes with number of make targets which can be used for testing and
benchmarking:

- ``test`` performs testing of the binary.
- ``bench`` runs benchmarks.
- ``cover`` produces coverage.
- ``lint`` runs set of linters on the code base.

## Contributing

To contribute, fork this repository and make your changes, and then make a Pull
Request. A Pull Request requires approval of the admin team and a successful
CI build.

## How to Cite

To cite CIRCL, use one of the following formats and update the version and date you accessed this project.

APA Style

```
Faz-Hernandez, A. and Kwiatkowski, K. (2019). Introducing CIRCL:
An Advanced Cryptographic Library. Cloudflare. Available at
https://github.com/cloudflare/circl. v1.6.3 Accessed Jan, 2026.
```

BibTeX Source

```bibtex
@manual{circl,
  title        = {Introducing CIRCL: An Advanced Cryptographic Library},
  author       = {Armando Faz-Hernandez and Kris Kwiatkowski},
  organization = {Cloudflare},
  abstract     = {{CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library) is
                   a collection of cryptographic primitives written in Go. The goal
                   of this library is to be used as a tool for experimental
                   deployment of cryptographic algorithms targeting Post-Quantum (PQ)
                   and Elliptic Curve Cryptography (ECC).}},
  note         = {Available at \url{https://github.com/cloudflare/circl}. v1.6.3 Accessed Jan, 2026},
  month        = jun,
  year         = {2019}
}
```

CFF Style

See attached [CITATION.cff](CITATION.cff) file.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
