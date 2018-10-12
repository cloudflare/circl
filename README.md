# CIRCL

Cloudflare Interoperable, Reusable Cryptographic Library written in Go

## Implemented primitives
* dh/
    - SIDH
* hash/
    - SHA3/
        * cSHAKE, SHAKE
* kem/
    - SIKE

## Make targets

* ``test``: performs testing of the binary
* ``bench``: runs benchmarks
* ``cover``: produces coverage
* ``go_vendor``: produces sources that can be directly coppied to go/vendor directory
