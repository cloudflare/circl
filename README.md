# CIRCL

Cloudflare Interoperable, Reusable Cryptographic Library written in Go

## Implemented primitives
* dh/
    - SIDH
* ecc/
    - P-384
* hash/
    - SHA3/
        * cSHAKE, SHAKE
* kem/
    - SIKE

## Make targets

* ``test``: performs testing of the binary
* ``bench``: runs benchmarks
* ``cover``: produces coverage
* ``vendor``: produces sources that can be directly copied to a ``go/vendor`` directory
