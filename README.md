# CIRCL

Cloudflare Interoperable, Reusable Cryptographic Library written in Go

## Implemented primitives
* dh/
    - SIDH
* ecc/
    - P-384 (note that this implementation is not constant-time)
* ecdhx/
    - ECDH/x448
    - ECDH/x25519
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
* ``generate``: generates source from templates.