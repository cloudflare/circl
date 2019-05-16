# CIRCL
[![CircleCI](https://circleci.com/gh/cloudflare/circl/tree/master.svg?style=svg&circle-token=a184a4d0cbff045907c8061bda35fc17dab465dc)](https://circleci.com/gh/cloudflare/circl/tree/master)

Cloudflare Interoperable, Reusable Cryptographic Library written in Go

## Implemented primitives
* dh/
    - SIDH
* ecc/
    - ecc/p384: elliptic curve operations for curve P-384.
* ecdh/
    - ECDH/x448
    - ECDH/x25519
* hash/
    - SHA3/
        * cSHAKE, SHAKE
* kem/
    - SIKE
* math/
    - Contains some utility functions for converting big integer numbers.

## Make targets

* ``test``: performs testing of the binary
* ``bench``: runs benchmarks
* ``cover``: produces coverage
* ``vendor``: produces sources that can be directly copied to a ``go/vendor`` directory
* ``generate``: generates source from templates.
